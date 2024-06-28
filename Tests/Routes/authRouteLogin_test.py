import unittest
import requests
import json

class RouteTest(unittest.TestCase):
    
    API_URL = os.getenv('API_URL')
    SIGNUP_URL = API_URL + "/login"
    payload = {'email': "albus.dumbledore@hogsmede.com", 'password': "Albus_123!"}
    missingPayload = {'email': "", 'password': ""}
    invalidPayload = {'email': 1234, 'password': True}
    wrongHeaders = {'wrong-header-type': 'application/xml'}
    rightHeaders = {'Content-Type' : 'application/json'}
    
    def test_signup_route(self):
        r = requests.get(self.SIGNUP_URL)
        self.assertEqual(r.status_code, 405, msg="Incorrect HTTP METHOD")
    
    def test_missing_headers(self):
        r = requests.post(self.SIGNUP_URL, data=json.dumps(self.payload), headers=self.wrongHeaders).json()  
        self.assertEqual(r['code'], "MISSING_REQUIRED_HEADERS")
        
    def test_invalid_type(self):
        r = requests.post(self.SIGNUP_URL, data=json.dumps(self.invalidPayload), headers=self.rightHeaders).json()
        self.assertEqual(r['code'], "INVALID_TYPE")
    
    def test_missing_data(self):
        r = requests.post(self.SIGNUP_URL, data=json.dumps(self.missingPayload), headers=self.rightHeaders).json()
        self.assertEqual(r['code'], "MISSING_REQUIRED_VALUES")
    
    def test_initializing_tables(self):
        r = requests.post(self.SIGNUP_URL, data=json.dumps(self.payload), headers=self.rightHeaders).json()
        self.assertEqual(r['error'], True)
        self.assertEqual(r['code'], "DB_TABLE_ERROR")
  
    
    

if __name__ == '__main__':
    unittest.main()
    