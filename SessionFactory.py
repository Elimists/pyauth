from DBConnector import DBConnector
from datetime import timedelta

class SessionFactory:

    def __init__(self):
        self.db_con = DBConnector()

    
    def createSession(self, sessionId, userEmail, ipAddress):
        currentDBTime = self.db_con.getCurrentDBDateTime()[0][0] 
        expiresOn = currentDBTime + timedelta(hours=12)
        sql = {
            'statement': ("INSERT INTO sessions "
                            "(sessionId, userEmail, ipAddress, expiresOn) "
                            "VALUES (%s, %s, %s, %s)"),
            'values': [sessionId, userEmail, ipAddress, expiresOn]
        }
        
        self.db_con.execute(sql)


    def getSessionData(self, sessionId):
        sql = {
            'statement': ("SELECT sessionId, userEmail, ipAddress, expiresOn "
                            "FROM sessions "
                            "WHERE sessionId = %s"),
            'values': [sessionId]
        }

        result = self.db_con.fetch(sql)[0]
        sessionData = {
            'sessionId': result[0],
            'userEmail': result[1],
            'ipAddress': result[2],
            'expiresOn': result[3]
        }
        return sessionData
    

    def getSessionExpiryTime(self, sessionId):
        sql = {
            'statement': ("SELECT expiresOn "
                            "FROM sessions "
                            "WHERE sessionId = %s"),
            'values': [sessionId]
        }

        result = self.db_con.fetch(sql)[0]
        sessionData = {
            'expiresOn': result[0]
        }
        return sessionData['expiresOn']
    
    
    def sessionIdExists(self, sessionId):
        sql = {
            'statement': ("SELECT sessionId FROM sessions "
                            "WHERE sessionId = %s"),
            'values': [sessionId]
        }

        result = self.db_con.fetch(sql)
        if len(result) == 0:
            return False
        return True


    def addHoursToSesionExpiryTime(self, sessionId, hourToAdd):
        currentDBTime = self.db_con.getCurrentDBDateTime()[0][0] 
        expiresOn = currentDBTime + timedelta(hours=hourToAdd)
        sql = {
            'statement': ("UPDATE sessions "
                            "SET expiresOn = %s"
                            "WHERE sessionId = %s"),
            'values': [expiresOn, sessionId]
        }

        self.db_con.execute(sql)


    def isSessionAboutToExpire(self, sessionId):
        currentDBTime = self.db_con.getCurrentDBDateTime()[0][0]
        sql = {
            'statement': ("SELECT expiresOn FROM sessions "
                            "WHERE sessionId = %s"),
            'values': [sessionId]
        } 
        expiryTime = self.db_con.fetch(sql)[0][0]
        duration = expiryTime - currentDBTime
        duration_in_s = duration.total_seconds()
        duration_in_minutes = divmod(duration_in_s, 60)[0]
    
        if duration_in_minutes <= 45:
            return True
        return False

    
    def sessionHasExpired(self, sessionId):
        currentDBTime = self.db_con.getCurrentDBDateTime()[0][0]
        sql = {
            'statement': ("SELECT expiresOn FROM sessions "
                            "WHERE sessionId = %s"),
            'values': [sessionId]
        }
        expiryTime = self.db_con.fetch(sql)[0][0]

        if currentDBTime > expiryTime:
            return True
        return False
    
    
    def deleteSession(self, sessionId):
        sql = {
            'statement': ("DELETE FROM sessions "
                            "WHERE sessionId = %s"),
            'values': [sessionId]    
        }

        self.db_con.execute(sql)


sf = SessionFactory()
#sf.createSession('akdurklwkKlkjd', 'pranp@neilsquire.ca', '127.0.0.1')
#sf.isSessionAboutToExpire('akdurklwkKlkjd')
#print(sf.sessionHasExpired('akdurklwkKlkjd'))
print(sf.getSessionExpiryTime("akdurklwkKlkjd"))