from Database import UserFactory
import unittest



class TestUserFactory(unittest.TestCase):
    
    def test_createUser(self):
        uf = UserFactory()
        result = uf.createUser('pandeydee@gmail.com', 'Deepak Pandey', 'hashedPasswordTest')
        self.assertEqual(result['error'], True)
        
        
if __name__ == '__main__':
    unittest.main()