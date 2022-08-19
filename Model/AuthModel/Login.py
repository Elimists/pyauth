from Model import UserModel

class Login(UserModel.User):
    
    password: str
    
    def __init__(self, email, password) -> None:
        super().__init__(email)
        self.password = password
    
    def getPassword(self) -> str:
        return self.password
    
    