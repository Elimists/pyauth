from Model import UserModel
import bcrypt

class SignUp(UserModel.User):
    
    password: bytes
    accountStatus: str = "Unverified"
    
    def __init__(self, email: str,  password: str) -> None:
        super().__init__(email)
        self.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    def getPassword(self) -> bytes:
        return self.password
    
    def getAccountStatus(self):
        return self.accountStatus
    
    def setAccountStatus(self, accountStatus):
        self.accountStatus = accountStatus
        