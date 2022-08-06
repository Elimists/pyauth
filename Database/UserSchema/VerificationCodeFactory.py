from unittest import result
from .DBConnector import DBConnector

class VerificationCodeFactory:

    def __init__(self):
        self.db_con = DBConnector()

    def saveVerificationCode(self, email, verificationCode):
        sql = {
            'statement': ("INSERT INTO verification_codes "
                            "(userEmail, verificationCode) "
                            "VALUES (%s, %s)"),
            'values': (email, verificationCode)
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