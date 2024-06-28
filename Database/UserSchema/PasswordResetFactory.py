from .DBConnector import DBConnector
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


    def updateTokenExpiration(self, passwordResetToken):
        currentDBTime = self.db_con.getCurrentDBDateTime()[0][0] 
        tokenExpiresOn = currentDBTime + timedelta(minutes=30)

        sql = {
            'statement': ("UPDATE password_reset_keys "
                            "SET passwordResetToken = %s, tokenExpiresOn = %s "
                            "WHERE userEmail = %s"),
            'values': [passwordResetToken, tokenExpiresOn, self.email]
        }

        self.db_con.execute(sql)

    def getPasswordResetTokenData(self):
        sql = {
            'statement': ("SELECT passwordResetToken, tokenExpiresOn FROM password_reset_keys "
                            "WHERE userEmail = %s"),
            'values': [self.email]
        }

        passResetToken = {'token': None, 'expiry': None}
        result = self.db_con.fetch(sql)
        if not result or len(result) == 0:
            return passResetToken
        
        passResetToken['token'] = result[0][0]
        passResetToken['expiry'] = result[0][0]
        return passResetToken
    

    def isTokenExpired(self):
        currentDBTime = self.db_con.getCurrentDBDateTime()[0][0]
        sql = {
            'statement': ("SELECT tokenExpiresOn From password_reset_keys "
                            "WHERE userEmail = %s"),
            'values': [self.email]
        }
        
        tokenExpiryTime = self.db_con.fetch(sql)[0][0]
        if currentDBTime > tokenExpiryTime:
            return True
        return False
    

    def deleteTokenData(self):
        sql = {
            'statement': ("DELETE FROM password_reset_keys "
                            "WHERE userEmail = %s"),
            'values': [self.email]
        }

        self.db_con.execute(sql)