import requests
import sys
import json
import io
from datetime import datetime

class AITenderGuardianTester:
    def __init__(self, base_url="https://ai-tender-guardian.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED: {details}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details
        })

    def test_root_endpoint(self):
        """Test the root API endpoint"""
        try:
            response = requests.get(f"{self.api_url}/", timeout=10)
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            if success:
                data = response.json()
                details += f", Message: {data.get('message', 'N/A')}"
            self.log_test("Root Endpoint", success, details)
            return success
        except Exception as e:
            self.log_test("Root Endpoint", False, str(e))
            return False

    def test_seal_bid(self):
        """Test bid sealing endpoint with file upload"""
        try:
            # Create a test file
            test_content = b"This is a test bid document with sensitive information."
            test_file = io.BytesIO(test_content)
            test_file.name = "test_bid.txt"
            
            # Prepare form data
            files = {
                'file': ('test_bid.txt', test_file, 'text/plain')
            }
            data = {
                'tender_id': 'TENDER-TEST-001'
            }
            
            response = requests.post(
                f"{self.api_url}/seal-bid", 
                files=files, 
                data=data,
                timeout=30
            )
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                result = response.json()
                if all(key in result for key in ['success', 'bidHash', 'bidderId', 'message']):
                    details += f", BidHash: {result['bidHash'][:20]}..., BidderId: {result['bidderId'][:8]}..."
                    # Store for audit log test
                    self.test_bid_hash = result['bidHash']
                    self.test_bidder_id = result['bidderId']
                else:
                    success = False
                    details += ", Missing required fields in response"
            else:
                try:
                    error_data = response.json()
                    details += f", Error: {error_data.get('detail', 'Unknown error')}"
                except:
                    details += f", Raw response: {response.text[:100]}"
            
            self.log_test("Seal Bid", success, details)
            return success
            
        except Exception as e:
            self.log_test("Seal Bid", False, str(e))
            return False

    def test_compliance_check(self):
        """Test AI compliance checking"""
        try:
            payload = {
                "tenderRequirements": "Must include technical specifications, delivery timeline within 30 days, ISO certification required, minimum 2 years experience in similar projects.",
                "bidSummary": "We offer complete technical documentation, 45-day delivery timeline, have ISO 9001 certification, and 3 years experience in government projects."
            }
            
            response = requests.post(
                f"{self.api_url}/check-compliance",
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=60  # AI calls can take longer
            )
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                result = response.json()
                if all(key in result for key in ['success', 'analysis', 'violations']):
                    details += f", Analysis length: {len(result['analysis'])} chars, Violations: {len(result['violations'])}"
                else:
                    success = False
                    details += ", Missing required fields in response"
            else:
                try:
                    error_data = response.json()
                    details += f", Error: {error_data.get('detail', 'Unknown error')}"
                except:
                    details += f", Raw response: {response.text[:100]}"
            
            self.log_test("AI Compliance Check", success, details)
            return success
            
        except Exception as e:
            self.log_test("AI Compliance Check", False, str(e))
            return False

    def test_tender_update(self):
        """Test n8n webhook endpoint"""
        try:
            payload = {
                "tenderId": "TENDER-TEST-001",
                "updateContent": "Tender deadline extended by 7 days due to technical clarifications",
                "updatedBy": "admin"
            }
            
            response = requests.post(
                f"{self.api_url}/tender-update",
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                result = response.json()
                if all(key in result for key in ['success', 'updateHash', 'timestamp']):
                    details += f", UpdateHash: {result['updateHash'][:20]}..., Timestamp: {result['timestamp']}"
                else:
                    success = False
                    details += ", Missing required fields in response"
            else:
                try:
                    error_data = response.json()
                    details += f", Error: {error_data.get('detail', 'Unknown error')}"
                except:
                    details += f", Raw response: {response.text[:100]}"
            
            self.log_test("Tender Update (n8n webhook)", success, details)
            return success
            
        except Exception as e:
            self.log_test("Tender Update (n8n webhook)", False, str(e))
            return False

    def test_audit_log(self):
        """Test audit log retrieval"""
        try:
            response = requests.get(f"{self.api_url}/audit-log", timeout=10)
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                result = response.json()
                if isinstance(result, list):
                    details += f", Entries: {len(result)}"
                    if len(result) > 0:
                        # Check if our test bid is in the audit log
                        if hasattr(self, 'test_bid_hash'):
                            found_test_bid = any(entry.get('bidHash') == self.test_bid_hash for entry in result)
                            details += f", Test bid found: {found_test_bid}"
                        
                        # Validate structure of first entry
                        first_entry = result[0]
                        required_fields = ['tenderId', 'bidHash', 'timestamp', 'bidderId', 'status']
                        if all(field in first_entry for field in required_fields):
                            details += ", Structure valid"
                        else:
                            success = False
                            details += ", Invalid entry structure"
                else:
                    success = False
                    details += ", Response is not a list"
            else:
                try:
                    error_data = response.json()
                    details += f", Error: {error_data.get('detail', 'Unknown error')}"
                except:
                    details += f", Raw response: {response.text[:100]}"
            
            self.log_test("Audit Log", success, details)
            return success
            
        except Exception as e:
            self.log_test("Audit Log", False, str(e))
            return False

    def run_all_tests(self):
        """Run all backend tests"""
        print(f"🚀 Starting AI Tender Guardian Backend Tests")
        print(f"📍 Testing against: {self.base_url}")
        print("=" * 60)
        
        # Test in logical order
        tests = [
            self.test_root_endpoint,
            self.test_seal_bid,
            self.test_compliance_check,
            self.test_tender_update,
            self.test_audit_log
        ]
        
        for test in tests:
            test()
            print()
        
        # Summary
        print("=" * 60)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return True
        else:
            print("⚠️  Some tests failed. Check details above.")
            return False

def main():
    tester = AITenderGuardianTester()
    success = tester.run_all_tests()
    
    # Save detailed results
    with open('/app/backend_test_results.json', 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'total_tests': tester.tests_run,
            'passed_tests': tester.tests_passed,
            'success_rate': f"{(tester.tests_passed/tester.tests_run)*100:.1f}%",
            'results': tester.test_results
        }, f, indent=2)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())