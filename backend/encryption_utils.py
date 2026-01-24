import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def get_encryption_key():
    """Get AES-256 key from environment or use dev fallback"""
    key = os.environ.get('ENCRYPTION_KEY', 'dev_aes_256_key_32_bytes_long_12345678901234567890')
    # Ensure key is exactly 32 bytes for AES-256
    return key.encode('utf-8')[:32].ljust(32, b'0')

def encrypt_file_content(file_content: bytes) -> tuple[bytes, bytes]:
    """Encrypt file content using AES-256 CBC mode
    Returns: (encrypted_content, iv)
    """
    key = get_encryption_key()
    iv = get_random_bytes(16)  # AES block size
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad content to AES block sizes
    padded_content = pad(file_content, AES.block_size)
    encrypted_content = cipher.encrypt(padded_content)
    
    return encrypted_content, iv

def generate_sha3_512_hash(content: bytes) -> str:
    """Generate SHA-3-512 hash of content"""
    return hashlib.sha3_512(content).hexdigest()

def generate_sha256_hash(content: str) -> str:
    """Generate SHA-256 hash for tender updates"""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()
