#!/usr/bin/env python3
"""
ParaSafe-Lite Backend API Testing
Tests all backend endpoints and functionality
"""

import requests
import json
import sys
import time
from datetime import datetime

class ParaSafeAPITester:
    def __init__(self, base_url="https://e413e54c-3789-41f0-a2cc-7aa6dd6a8447.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.session = requests.Session()
        self.session.timeout = 30  # Longer timeout for security scans

    def log_test(self, name, success, details=""):
        """Log test results"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED")
        
        if details:
            print(f"   Details: {details}")
        print()

    def test_health_endpoint(self):
        """Test the health check endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            
            if response.status_code == 200:
                data = response.json()
                expected_fields = ["status", "service", "version"]
                has_all_fields = all(field in data for field in expected_fields)
                
                if has_all_fields and data.get("status") == "healthy":
                    self.log_test("Health Check", True, f"Service: {data.get('service')}, Version: {data.get('version')}")
                    return True
                else:
                    self.log_test("Health Check", False, f"Missing fields or unhealthy status: {data}")
                    return False
            else:
                self.log_test("Health Check", False, f"Status code: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Health Check", False, f"Exception: {str(e)}")
            return False

    def test_scan_endpoint_valid_url(self):
        """Test scanning with a valid URL"""
        test_url = "https://example.com"
        
        try:
            payload = {"url": test_url}
            response = self.session.post(
                f"{self.base_url}/api/scan",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check required fields in response
                required_fields = ["scan_id", "target_url", "scan_time", "summary", "vulnerabilities", "scan_info"]
                missing_fields = [field for field in required_fields if field not in data]
                
                if not missing_fields:
                    # Check summary structure
                    summary = data.get("summary", {})
                    risk_levels = ["high", "medium", "low", "info"]
                    has_risk_counts = all(level in summary for level in risk_levels)
                    
                    if has_risk_counts:
                        total_vulns = sum(summary.values())
                        self.log_test("Scan Valid URL", True, 
                                    f"Found {total_vulns} total vulnerabilities: {summary}")
                        return data
                    else:
                        self.log_test("Scan Valid URL", False, f"Missing risk level counts in summary: {summary}")
                        return None
                else:
                    self.log_test("Scan Valid URL", False, f"Missing required fields: {missing_fields}")
                    return None
            else:
                self.log_test("Scan Valid URL", False, f"Status code: {response.status_code}, Response: {response.text}")
                return None
                
        except Exception as e:
            self.log_test("Scan Valid URL", False, f"Exception: {str(e)}")
            return None

    def test_scan_endpoint_invalid_url(self):
        """Test scanning with an invalid URL"""
        test_url = "not-a-valid-url"
        
        try:
            payload = {"url": test_url}
            response = self.session.post(
                f"{self.base_url}/api/scan",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            # Should return an error (4xx or 5xx)
            if response.status_code >= 400:
                self.log_test("Scan Invalid URL", True, f"Correctly rejected invalid URL with status {response.status_code}")
                return True
            else:
                self.log_test("Scan Invalid URL", False, f"Should have rejected invalid URL but got status {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Scan Invalid URL", False, f"Exception: {str(e)}")
            return False

    def test_scan_endpoint_unreachable_url(self):
        """Test scanning with an unreachable URL"""
        test_url = "https://this-domain-should-not-exist-12345.com"
        
        try:
            payload = {"url": test_url}
            response = self.session.post(
                f"{self.base_url}/api/scan",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            # Should handle gracefully - either return error or empty results
            if response.status_code in [200, 400, 500]:
                self.log_test("Scan Unreachable URL", True, f"Handled unreachable URL gracefully with status {response.status_code}")
                return True
            else:
                self.log_test("Scan Unreachable URL", False, f"Unexpected status code: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Scan Unreachable URL", False, f"Exception: {str(e)}")
            return False

    def test_scan_history_endpoint(self):
        """Test getting scan history"""
        try:
            response = self.session.get(f"{self.base_url}/api/scans")
            
            if response.status_code == 200:
                data = response.json()
                
                if "scans" in data and isinstance(data["scans"], list):
                    scan_count = len(data["scans"])
                    self.log_test("Scan History", True, f"Retrieved {scan_count} scans from history")
                    return data["scans"]
                else:
                    self.log_test("Scan History", False, f"Invalid response structure: {data}")
                    return None
            else:
                self.log_test("Scan History", False, f"Status code: {response.status_code}")
                return None
                
        except Exception as e:
            self.log_test("Scan History", False, f"Exception: {str(e)}")
            return None

    def test_get_specific_scan(self, scan_id):
        """Test getting a specific scan by ID"""
        if not scan_id:
            self.log_test("Get Specific Scan", False, "No scan ID provided")
            return False
            
        try:
            response = self.session.get(f"{self.base_url}/api/scan/{scan_id}")
            
            if response.status_code == 200:
                data = response.json()
                
                if "scan_id" in data and data["scan_id"] == scan_id:
                    self.log_test("Get Specific Scan", True, f"Retrieved scan {scan_id}")
                    return True
                else:
                    self.log_test("Get Specific Scan", False, f"Scan ID mismatch or missing: {data}")
                    return False
            elif response.status_code == 404:
                self.log_test("Get Specific Scan", True, f"Correctly returned 404 for scan {scan_id}")
                return True
            else:
                self.log_test("Get Specific Scan", False, f"Status code: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Get Specific Scan", False, f"Exception: {str(e)}")
            return False

    def test_vulnerability_detection(self):
        """Test that the scanner actually detects vulnerabilities"""
        # Test with httpbin.org which should have some security headers missing
        test_url = "http://httpbin.org"  # Using HTTP to trigger HTTPS vulnerability
        
        try:
            payload = {"url": test_url}
            response = self.session.post(
                f"{self.base_url}/api/scan",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                # Should detect at least the HTTP vulnerability
                http_vuln_found = any("HTTP" in vuln.get("title", "") for vuln in vulnerabilities)
                
                if http_vuln_found:
                    self.log_test("Vulnerability Detection", True, 
                                f"Detected {len(vulnerabilities)} vulnerabilities including HTTP issue")
                    return data
                else:
                    self.log_test("Vulnerability Detection", False, 
                                f"Expected to find HTTP vulnerability but found: {[v.get('title') for v in vulnerabilities]}")
                    return None
            else:
                self.log_test("Vulnerability Detection", False, f"Status code: {response.status_code}")
                return None
                
        except Exception as e:
            self.log_test("Vulnerability Detection", False, f"Exception: {str(e)}")
            return None

    def test_export_pdf(self, scan_result):
        """Test PDF export functionality"""
        if not scan_result:
            self.log_test("Export PDF", False, "No scan result provided")
            return False
            
        try:
            response = self.session.post(
                f"{self.base_url}/api/export/pdf",
                json=scan_result,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                # Check content type
                content_type = response.headers.get("content-type", "")
                if "application/pdf" in content_type:
                    # Check content disposition for filename
                    content_disposition = response.headers.get("content-disposition", "")
                    expected_filename = f"parasafe-report-{scan_result['scan_id']}.pdf"
                    
                    if expected_filename in content_disposition:
                        # Check that we got actual PDF content
                        content_length = len(response.content)
                        if content_length > 1000:  # PDF should be substantial
                            self.log_test("Export PDF", True, 
                                        f"Generated PDF ({content_length} bytes) with correct filename")
                            return True
                        else:
                            self.log_test("Export PDF", False, f"PDF too small: {content_length} bytes")
                            return False
                    else:
                        self.log_test("Export PDF", False, f"Incorrect filename in header: {content_disposition}")
                        return False
                else:
                    self.log_test("Export PDF", False, f"Wrong content type: {content_type}")
                    return False
            else:
                self.log_test("Export PDF", False, f"Status code: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Export PDF", False, f"Exception: {str(e)}")
            return False

    def test_export_word(self, scan_result):
        """Test Word export functionality"""
        if not scan_result:
            self.log_test("Export Word", False, "No scan result provided")
            return False
            
        try:
            response = self.session.post(
                f"{self.base_url}/api/export/word",
                json=scan_result,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                # Check content type
                content_type = response.headers.get("content-type", "")
                if "wordprocessingml" in content_type:
                    # Check content disposition for filename
                    content_disposition = response.headers.get("content-disposition", "")
                    expected_filename = f"parasafe-report-{scan_result['scan_id']}.docx"
                    
                    if expected_filename in content_disposition:
                        # Check that we got actual Word content
                        content_length = len(response.content)
                        if content_length > 1000:  # Word doc should be substantial
                            self.log_test("Export Word", True, 
                                        f"Generated Word doc ({content_length} bytes) with correct filename")
                            return True
                        else:
                            self.log_test("Export Word", False, f"Word doc too small: {content_length} bytes")
                            return False
                    else:
                        self.log_test("Export Word", False, f"Incorrect filename in header: {content_disposition}")
                        return False
                else:
                    self.log_test("Export Word", False, f"Wrong content type: {content_type}")
                    return False
            else:
                self.log_test("Export Word", False, f"Status code: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Export Word", False, f"Exception: {str(e)}")
            return False

    def test_export_json(self, scan_result):
        """Test JSON export functionality"""
        if not scan_result:
            self.log_test("Export JSON", False, "No scan result provided")
            return False
            
        try:
            response = self.session.post(
                f"{self.base_url}/api/export/json",
                json=scan_result,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                # Check content disposition for filename
                content_disposition = response.headers.get("content-disposition", "")
                expected_filename = f"parasafe-report-{scan_result['scan_id']}.json"
                
                if expected_filename in content_disposition:
                    # Parse JSON response
                    try:
                        json_data = response.json()
                        
                        # Check required fields in JSON export
                        required_fields = ["report_type", "generated_at", "scan_data"]
                        missing_fields = [field for field in required_fields if field not in json_data]
                        
                        if not missing_fields:
                            # Check that scan_data contains original scan result
                            scan_data = json_data.get("scan_data", {})
                            if scan_data.get("scan_id") == scan_result["scan_id"]:
                                self.log_test("Export JSON", True, 
                                            f"Generated JSON export with correct structure and scan ID")
                                return True
                            else:
                                self.log_test("Export JSON", False, f"Scan ID mismatch in JSON export")
                                return False
                        else:
                            self.log_test("Export JSON", False, f"Missing fields in JSON: {missing_fields}")
                            return False
                    except json.JSONDecodeError as e:
                        self.log_test("Export JSON", False, f"Invalid JSON response: {str(e)}")
                        return False
                else:
                    self.log_test("Export JSON", False, f"Incorrect filename in header: {content_disposition}")
                    return False
            else:
                self.log_test("Export JSON", False, f"Status code: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Export JSON", False, f"Exception: {str(e)}")
            return False

    def run_all_tests(self):
        """Run all backend tests"""
        print("🔍 Starting ParaSafe-Lite Backend API Tests")
        print(f"🌐 Testing against: {self.base_url}")
        print("=" * 60)
        
        # Test 1: Health check
        health_ok = self.test_health_endpoint()
        
        if not health_ok:
            print("❌ Backend health check failed. Stopping tests.")
            return False
        
        # Test 2: Valid URL scan
        scan_result = self.test_scan_endpoint_valid_url()
        scan_id = scan_result.get("scan_id") if scan_result else None
        
        # Test 3: Invalid URL handling
        self.test_scan_endpoint_invalid_url()
        
        # Test 4: Unreachable URL handling
        self.test_scan_endpoint_unreachable_url()
        
        # Test 5: Scan history
        self.test_scan_history_endpoint()
        
        # Test 6: Get specific scan (if we have a scan ID)
        if scan_id:
            self.test_get_specific_scan(scan_id)
        
        # Test 7: Vulnerability detection (returns scan result for export tests)
        vuln_scan_result = self.test_vulnerability_detection()
        
        # Test 8-10: Export functionality (use vulnerability scan result)
        export_scan_result = vuln_scan_result if vuln_scan_result else scan_result
        if export_scan_result:
            print("🔄 Testing Export Functionality...")
            self.test_export_pdf(export_scan_result)
            self.test_export_word(export_scan_result)
            self.test_export_json(export_scan_result)
        else:
            print("⚠️  Skipping export tests - no scan result available")
        
        # Print summary
        print("=" * 60)
        print(f"📊 Test Summary: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All backend tests passed!")
            return True
        else:
            print(f"⚠️  {self.tests_run - self.tests_passed} tests failed")
            return False

def main():
    """Main test execution"""
    tester = ParaSafeAPITester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())