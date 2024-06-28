from .DBConnector import DBConnector
from datetime import timedelta

class VerificationCodeFactory:

    def __init__(self):
        self.db_con = DBConnector()

    def saveVerificationCode(self, email, verificationCode):
        currentDBTime = self.db_con.getCurrentDBDateTime()[0][0] 
        expiresOn = currentDBTime + timedelta(minutes=20)
        sql = {
            'statement': ("INSERT INTO verification_codes "
                            "(userEmail, verificationCode, expiresOn) "
                            "VALUES (%s, %s, %s)"),
            'values': (email, verificationCode, expiresOn)
        }
        self.db_con.execute(sql)
        
    
    def updateVerificationCode(self, email, verificationCode):
        sql = {
            'statement': ("UPDATE verification_codes "
                            "SET verificationCode = %s "
                            "WHERE userEmail = %s"),
            'values': [verificationCode, email]
        }
        self.db_con.execute(sql)
    

    def getVerificationCode(self, email):
        sql = {
            'statement': ("SELECT verificationCode FROM verification_codes "
                            "WHERE userEmail = %s"),
            'values': [email]
        }

        result = self.db_con.fetch(sql)
        if len(result) == 0:
            return None
        
        return {'verificationCode': result[0][0]}

    def deleteVerificationCode(self, email):
        sql = {
            'statement': ("DELETE FROM verification_codes "
                            "WHERE userEmail = %s"),
            'values': [email]
        }
        self.db_con.execute(sql)
        
    def verificationCodeHasExpired(self, email):
        sql = {
            'statement': ("SELECT expiresOn FROM verification_codes "
                          "WHERE userEmail = %s"),
            'values': [email]
        }
        expiryTime = self.db_con.fetch(sql)[0][0]
        currentDBTime = self.db_con.getCurrentDBDateTime()[0][0] 
        if currentDBTime <= expiryTime:
            return False
        return True