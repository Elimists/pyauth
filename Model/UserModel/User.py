class User:

    email: str
    
    def __init__(self, email) -> None:
        self.email = email
        
    def getEmail(self) -> str:
        return self.email

    def setEmail(self, email: str):
        self.email = email 