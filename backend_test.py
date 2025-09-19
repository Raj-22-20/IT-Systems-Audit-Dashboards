import requests
import sys
import json
from datetime import datetime

class ITAuditDashboardTester:
    def __init__(self, base_url="https://risk-control-hub.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.sample_user_id = None

    def run_test(self, name, method, endpoint, expected_status, data=None, params=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers)

            print(f"   Status Code: {response.status_code}")
            
            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ PASSED - {name}")
                try:
                    response_data = response.json()
                    if isinstance(response_data, dict) and len(str(response_data)) < 500:
                        print(f"   Response: {response_data}")
                    elif isinstance(response_data, list):
                        print(f"   Response: List with {len(response_data)} items")
                    return True, response_data
                except:
                    return True, {}
            else:
                print(f"❌ FAILED - Expected {expected_status}, got {response.status_code}")
                try:
                    error_detail = response.json()
                    print(f"   Error: {error_detail}")
                except:
                    print(f"   Error: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ FAILED - Network Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root API Endpoint", "GET", "", 200)

    def test_generate_sample_data(self):
        """Test sample data generation"""
        success, response = self.run_test(
            "Generate Sample Data",
            "POST",
            "generate-sample-data",
            200
        )
        if success:
            print(f"   Generated {response.get('logs_generated', 0)} logs and {response.get('violations_generated', 0)} violations")
        return success, response

    def test_dashboard_stats(self):
        """Test dashboard statistics"""
        success, response = self.run_test(
            "Dashboard Statistics",
            "GET",
            "dashboard/stats",
            200
        )
        if success:
            required_fields = ['total_access_logs', 'active_violations', 'high_risk_users', 
                             'failed_logins_today', 'privilege_escalations_week', 'compliance_score']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                print(f"   ⚠️  Missing fields: {missing_fields}")
            else:
                print(f"   ✅ All required fields present")
        return success, response

    def test_access_logs(self):
        """Test access logs endpoint with different filters"""
        # Test basic access logs
        success1, response1 = self.run_test(
            "Access Logs - Basic",
            "GET",
            "access-logs",
            200,
            params={"limit": 10}
        )
        
        # Test with violations filter
        success2, response2 = self.run_test(
            "Access Logs - Violations Only",
            "GET",
            "access-logs",
            200,
            params={"violations_only": True, "limit": 5}
        )
        
        # Test with risk level filter
        success3, response3 = self.run_test(
            "Access Logs - High Risk",
            "GET",
            "access-logs",
            200,
            params={"risk_level": "high", "limit": 5}
        )
        
        # Extract sample user_id for later tests
        if success1 and response1 and len(response1) > 0:
            self.sample_user_id = response1[0].get('user_id')
            print(f"   📝 Sample user_id for later tests: {self.sample_user_id}")
        
        return success1 and success2 and success3, response1

    def test_violations(self):
        """Test violations endpoint"""
        success, response = self.run_test(
            "Security Violations",
            "GET",
            "violations",
            200,
            params={"limit": 10}
        )
        return success, response

    def test_analytics_trends(self):
        """Test analytics trends"""
        success, response = self.run_test(
            "Analytics Trends",
            "GET",
            "analytics/trends",
            200
        )
        if success:
            required_keys = ['access_trends', 'top_violation_types', 'risk_distribution']
            missing_keys = [key for key in required_keys if key not in response]
            if missing_keys:
                print(f"   ⚠️  Missing keys: {missing_keys}")
            else:
                print(f"   ✅ All required analytics keys present")
        return success, response

    def test_sql_queries(self):
        """Test SQL query execution with different query types"""
        query_types = [
            'unauthorized_access',
            'privilege_escalation', 
            'segregation_conflicts',
            'failed_logins',
            'off_hours_access'
        ]
        
        all_success = True
        for query_type in query_types:
            success, response = self.run_test(
                f"SQL Query - {query_type}",
                "POST",
                "sql-query",
                200,
                data={"query_type": query_type}
            )
            if success:
                print(f"   📊 Query returned {response.get('results_count', 0)} results")
            all_success = all_success and success
            
        return all_success, {}

    def test_user_risk_assessment(self):
        """Test user risk assessment"""
        if not self.sample_user_id:
            print("⚠️  Skipping risk assessment test - no sample user_id available")
            return True, {}
            
        success, response = self.run_test(
            f"User Risk Assessment - {self.sample_user_id}",
            "GET",
            f"users/{self.sample_user_id}/risk-assessment",
            200
        )
        if success:
            required_fields = ['user_id', 'overall_risk_score', 'risk_level', 'risk_factors', 'recommendations']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                print(f"   ⚠️  Missing fields: {missing_fields}")
            else:
                print(f"   ✅ Risk assessment complete - Level: {response.get('risk_level')}")
        return success, response

    def test_violation_resolution(self):
        """Test violation resolution"""
        # First get a violation to resolve
        success, violations = self.run_test(
            "Get Violations for Resolution Test",
            "GET",
            "violations",
            200,
            params={"limit": 1}
        )
        
        if not success or not violations or len(violations) == 0:
            print("⚠️  No violations available to test resolution")
            return True, {}
        
        violation_id = violations[0].get('id')
        if not violation_id:
            print("⚠️  No violation ID found")
            return False, {}
            
        success, response = self.run_test(
            f"Resolve Violation - {violation_id}",
            "POST",
            f"violations/{violation_id}/resolve",
            200
        )
        return success, response

def main():
    print("🚀 Starting IT Audit Dashboard Backend API Testing")
    print("=" * 60)
    
    tester = ITAuditDashboardTester()
    
    # Test sequence
    tests = [
        ("Root Endpoint", tester.test_root_endpoint),
        ("Generate Sample Data", tester.test_generate_sample_data),
        ("Dashboard Stats", tester.test_dashboard_stats),
        ("Access Logs", tester.test_access_logs),
        ("Violations", tester.test_violations),
        ("Analytics Trends", tester.test_analytics_trends),
        ("SQL Queries", tester.test_sql_queries),
        ("User Risk Assessment", tester.test_user_risk_assessment),
        ("Violation Resolution", tester.test_violation_resolution),
    ]
    
    print(f"\n📋 Running {len(tests)} test categories...")
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            success, _ = test_func()
            if not success:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"❌ {test_name} crashed: {str(e)}")
    
    # Final results
    print(f"\n{'='*60}")
    print(f"📊 FINAL RESULTS")
    print(f"{'='*60}")
    print(f"✅ Tests Passed: {tester.tests_passed}")
    print(f"❌ Tests Failed: {tester.tests_run - tester.tests_passed}")
    print(f"📈 Success Rate: {(tester.tests_passed/tester.tests_run*100):.1f}%")
    
    if tester.tests_passed == tester.tests_run:
        print(f"\n🎉 ALL TESTS PASSED! Backend API is working correctly.")
        return 0
    else:
        print(f"\n⚠️  Some tests failed. Check the details above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())