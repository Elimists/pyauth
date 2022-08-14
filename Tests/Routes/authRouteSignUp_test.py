import unittest
import requests
import json

class RouteTest(unittest.TestCase):
    
    API_URL = "http://127.0.0.1:5000"
    SIGNUP_URL = API_URL + "/signup"
    
    def test_signup_route(self):
        r = requests.get(self.SIGNUP_URL)
        self.assertEqual(r.status_code, 405, msg="Incorrect HTTP METHOD")
    
    #Testing wrong headers
    def test_header_result(self):
        payload = {'some': 'data'}
        headers = {'wrong-header-type': 'application/json'}

        r = requests.post(self.SIGNUP_URL, data=json.dumps(payload), headers=headers).json()  
        self.assertEqual(r['code'], "MISSING_REQUIRED_HEADERS")

    #Testing for missing json packet
    def test_missing_data(self):
        payload = {}
        headers = {'Content-Type': 'application/json'}
        
        r = requests.post(self.SIGNUP_URL, data=json.dumps(payload), headers=headers).json()
        self.assertEqual(r['code'], "MISSING_REQUIRED_KEYS")
    
    #Testing for missing values
    def test_missing_data_values(self):
        payload = {'email': '', 'name': '', 'password': ''}
        headers = {'Content-Type': 'application/json'}
        
        r = requests.post(self.SIGNUP_URL, data=json.dumps(payload), headers=headers).json()
        self.assertEqual(r['code'], "MISSING_REQUIRED_VALUES")

    #Testing for wrond value type
    def test_wrong_data_type(self):
        payload = {'email': 4, 'name': 6, 'password': 9}
        headers = {'Content-Type': 'application/json'}
        
        r = requests.post(self.SIGNUP_URL, data=json.dumps(payload), headers=headers).json()
        self.assertEqual(r['code'], "INVALID_TYPE")
        
    #Testing for invalid email
    def test_invalid_email(self):
        payload = {'email': "asldkfjsld3!la.com", 'name': "Pran Pandey", 'password': "helloWorld!12"}
        headers = {'Content-Type': 'application/json'}
        
        r = requests.post(self.SIGNUP_URL, data=json.dumps(payload), headers=headers).json()
        self.assertEqual(r['code'], "INVALID_EMAIL")
    
    #Testing for invalid name
    def test_invalid_name(self):
        payload = {'email': "pran.pandey@hotmail.com", 'name': "Pran{3221/SD", 'password': "helloWorld!12"}
        headers = {'Content-Type': 'application/json'}
        
        r = requests.post(self.SIGNUP_URL, data=json.dumps(payload), headers=headers).json()
        self.assertEqual(r['code'], "INVALID_NAME")
            
    #Testing for weak password
    def test_weak_password(self):
        payload = {'email': "pran.pandey@hotmail.com", 'name': "Pran Pandey", 'password': "asd12"}
        headers = {'Content-Type': 'application/json'}
        
        r = requests.post(self.SIGNUP_URL, data=json.dumps(payload), headers=headers).json()
        self.assertEqual(r['code'], "WEAK_PASSWORD")
    
    #Testing user already exists
    def test_user_exists(self):
        payload = {'email': "pandey.pran@gmail.com", 'name': "Pran Pandey", 'password': "Abc@123!"}
        headers = {'Content-Type': 'application/json'}
        
        r = requests.post(self.SIGNUP_URL, data=json.dumps(payload), headers=headers).json()
        self.assertEqual(r['code'], "DUPLICATE_USER")
        
    #Testing creating new user in db
    def test_new_user_creation(self):
        payload = {'email': "pranjal_pandey@hotmail.com", 'name': "Pranjal Pandey", 'password': "Abc@123!"}
        headers = {'Content-Type': 'application/json'}
        
        r = requests.post(self.SIGNUP_URL, data=json.dumps(payload), headers=headers).json()
        if r['code'] == "DUPLICATE_USER":
            self.assertEqual(r['code'], "DUPLICATE_USER")
        else:
            self.assertEqual(r['code'], "SUCCESS")
    
if __name__ == '__main__':
    unittest.main()
    