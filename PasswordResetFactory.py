from DBConnector import DBConnector
from datetime import datetime
from datetime import timedelta

class PasswordResetFactory:

    def __init__(self, email):
        self.db_con = DBConnector()
        self.email = email


    def savePasswordResetToken(self, passwordResetToken):
        currentDBTime = self.db_con.getCurrentDBDateTime()[0][0] 
        tokenExpiresOn = currentDBTime + timedelta(minutes=30)
     
        sql = {
            'statement': ("INSERT INTO password_reset_keys "
                            "(userEmail, passwordResetToken, tokenExpiresOn) "
                            "VALUES (%s, %s, %s)"),
            'values': [self.email, passwordResetToken, tokenExpiresOn]
        }
        self.db_con.execute(sql)

    
    def getPasswordResetTokenData(self):
        sql = {
            'statement': ("SELECT passwordResetToken, tokenExpiresOn FROM password_reset_keys "
                            "WHERE userEmail = %s"),
            'values': [self.email]
        }

        result = self.db_con.fetch(sql)
        passwordResetTokenData = {
            'token': result[0][0],
            'expiry': result[0][1]
        }
        return passwordResetTokenData
    

    
