from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import base64

from encryption_utils import encrypt_file_content, generate_sha3_512_hash, generate_sha256_hash
from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Models
class SealedBid(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    tenderId: str
    bidHash: str
    timestamp: str
    bidderId: str
    status: str = "SEALED"
    encryptedFileBase64: Optional[str] = None
    iv: Optional[str] = None

class SealBidResponse(BaseModel):
    success: bool
    bidHash: str
    message: str
    bidderId: str

class ComplianceCheckRequest(BaseModel):
    tenderRequirements: str
    bidSummary: str

class ComplianceCheckResponse(BaseModel):
    success: bool
    analysis: str
    violations: List[str]

class TenderUpdate(BaseModel):
    tenderId: str
    updateContent: str
    updatedBy: str = "system"

class TenderUpdateResponse(BaseModel):
    success: bool
    updateHash: str
    timestamp: str

class AuditLogEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    tenderId: str
    bidHash: str
    timestamp: str
    bidderId: str
    status: str

# Routes
@api_router.get("/")
async def root():
    return {"message": "AI Tender Guardian API", "version": "1.0"}

@api_router.post("/seal-bid", response_model=SealBidResponse)
async def seal_bid(
    file: UploadFile = File(...),
    tender_id: str = File(...)
):
    try:
        # Read file content
        file_content = await file.read()
        
        # Encrypt file using AES-256
        encrypted_content, iv = encrypt_file_content(file_content)
        
        # Generate SHA-3-512 hash of encrypted file
        bid_hash = generate_sha3_512_hash(encrypted_content)
        
        # Generate unique bidder ID
        bidder_id = str(uuid.uuid4())
        
        # Store metadata in database (NOT the file itself)
        timestamp = datetime.now(timezone.utc).isoformat()
        
        sealed_bid = {
            "tenderId": tender_id,
            "bidHash": bid_hash,
            "timestamp": timestamp,
            "bidderId": bidder_id,
            "status": "SEALED",
            "encryptedFileBase64": base64.b64encode(encrypted_content).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8')
        }
        
        await db.bids.insert_one(sealed_bid)
        
        return SealBidResponse(
            success=True,
            bidHash=bid_hash,
            message="Bid sealed successfully with AES-256 encryption",
            bidderId=bidder_id
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to seal bid: {str(e)}")

@api_router.post("/check-compliance", response_model=ComplianceCheckResponse)
async def check_compliance(request: ComplianceCheckRequest):
    try:
        # Initialize Gemini chat with Emergent LLM key
        api_key = os.environ.get('EMERGENT_LLM_KEY')
        if not api_key:
            raise HTTPException(status_code=500, detail="EMERGENT_LLM_KEY not configured")
        
        chat = LlmChat(
            api_key=api_key,
            session_id=f"compliance-{uuid.uuid4()}",
            system_message="You are a procurement compliance assistant. Analyze tender requirements and bid summaries for compliance violations."
        ).with_model("gemini", "gemini-3-flash-preview")
        
        # Create compliance check prompt
        prompt = f"""You are a procurement compliance assistant.

Tender requirements:
{request.tenderRequirements}

Bid summary:
{request.bidSummary}

Analyze the bid against tender requirements and list any violations or missing requirements in bullet points. Be specific and concise."""
        
        user_message = UserMessage(text=prompt)
        response = await chat.send_message(user_message)
        
        # Parse response for violations
        violations = []
        if response:
            lines = response.split('\n')
            for line in lines:
                line = line.strip()
                if line and (line.startswith('-') or line.startswith('•') or line.startswith('*')):
                    violations.append(line.lstrip('-•* ').strip())
        
        return ComplianceCheckResponse(
            success=True,
            analysis=response or "No violations detected",
            violations=violations if violations else ["No violations detected"]
        )
        
    except Exception as e:
        logging.error(f"Compliance check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Compliance check failed: {str(e)}")

@api_router.post("/tender-update", response_model=TenderUpdateResponse)
async def tender_update(update: TenderUpdate):
    """n8n webhook endpoint for governance triggers"""
    try:
        # Generate SHA-256 hash of the update
        update_content = f"{update.tenderId}:{update.updateContent}:{update.updatedBy}"
        update_hash = generate_sha256_hash(update_content)
        
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Store in tender_updates collection
        tender_update_doc = {
            "tenderId": update.tenderId,
            "updateContent": update.updateContent,
            "updatedBy": update.updatedBy,
            "updateHash": update_hash,
            "timestamp": timestamp
        }
        
        await db.tender_updates.insert_one(tender_update_doc)
        
        return TenderUpdateResponse(
            success=True,
            updateHash=update_hash,
            timestamp=timestamp
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log tender update: {str(e)}")

@api_router.get("/audit-log", response_model=List[AuditLogEntry])
async def get_audit_log():
    """Retrieve immutable audit log of all sealed bids"""
    try:
        # Fetch all bids, exclude _id and encrypted data
        bids = await db.bids.find(
            {},
            {"_id": 0, "tenderId": 1, "bidHash": 1, "timestamp": 1, "bidderId": 1, "status": 1}
        ).sort("timestamp", -1).to_list(1000)
        
        return bids
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch audit log: {str(e)}")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
