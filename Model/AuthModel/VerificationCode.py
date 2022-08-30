from Model import UserModel
import string, random

class VerificationCode(UserModel.User):
    
    CODE_LENGTH: int = 5
    activationCode: str = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(CODE_LENGTH))
    
    def __init__(self, email: str) -> None:
        super().__init__(email)
    
    def getVerificationCode(self) -> str:
        return self.activationCode

    def getNewVerificationCode(self):
        newActivationCode = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(self.CODE_LENGTH))
        self.activationCode = newActivationCode
        return self.activationCode