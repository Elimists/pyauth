from Model import UserModel

class UserDetails(UserModel.User):
    
    name: str = None
    bio: str = None
    
    def __init__(self, email: str):
        super().__init__(email)
    
    def setName(self, name: str):
        self.name = name
        
    def getName(self) -> str:
        return self.name
    
    def setBio(self, bio: str):
        self.bio = bio
        
    def getBio(self) -> str:
        return self.bio