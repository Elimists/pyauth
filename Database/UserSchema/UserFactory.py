from .DBConnector import DBConnector

class UserFactory():

    def __init__(self):
        self.db_con = DBConnector()


    def createUser(self, user) -> dict:
        sql = {
            'statement': ("INSERT INTO users "
                            "(email, password, accountStatus) "
                            "VALUES (%s, %s, %s)"),
            'values': (user.getEmail(), user.getUserPassword(), user.getAccountStatus())
        }
        
        try:
            self.db_con.execute(sql)
            return {"error": False, "message": "User created successfully", "code": "SUCCESS"}
        except Exception as e:
            return {'error': True, 'message': 'Could not create user', 'code': 'DATABASE_ERROR'}
     

    def getUserByEmail(self, email: str):
        sql = {
            'statement': ("SELECT email, name FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        try:
            return self.db_con.fetch(sql)
        except Exception as e:
            errorDict = e.__dict__
            return {'error': True, 'message': 'Database error!', 'code': errorDict['errno']}


    def getUserPassword(self, email: str):
        sql = {
            'statement': ("SELECT password FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        try:
            return self.db_con.fetch(sql)
        except Exception as e:
            errorDict = e.__dict__
            return {'error': True, 'message': 'Database error!', 'code': errorDict['errno']}

    
    def userAlreadyExistsInDB(self):
        sql = {
            'statement': ("SELECT email, name FROM users "
                            "WHERE email = %s"),
            'values': [self.email]
        }
        result = self.db_con.fetch(sql)
        if not result or len(result) == 0:
            return False
        
        return True


    def updateUserName(self, email: str, name: str):
        sql = {
            'statement': ("UPDATE users "
                            "SET name = %s "
                            "WHERE email = %s"),
            'values':[name, email]
        }
        try:
            self.db_con.execute(sql)
            return {'error': False, 'message': 'User name updated successfully!', 'code': 8008}
        except Exception as e:
            errorDict = e.__dict__
            return {'error': True, 'message': 'Database error!', 'code': errorDict['errno']}


    def updateUserPassword(self, email: str, password: str):
        sql = {
            'statement': ("UPDATE users "
                            "SET password = %s "
                            "WHERE email = %s"),
            'values': [password, email]
        }
        try:
            self.db_con.execute(sql)
            return {'error': False, 'message': 'User Password updated successfully', 'code': 8008}
        except Exception as e:
            errorDict = e.__dict__
            return {'error': False, 'message': 'Database error!', 'code': errorDict['error']}

    
    def updateUserAccountStatusToVerfied(self, email: str):
        sql = {
            'statement': ("UPDATE users "
                            "SET accountStatus = %s "
                            "WHERE email = %s"),
            'values': ["Verified", email]
        }
        try:
            self.db_con.execute(sql)
            return {'error':False, 'message': 'Updated user account status to verified', 'code': 8008}
        except Exception as e:
            errorDict = e.__dict__
            return {'error':True, 'message': 'Database error!', 'code': errorDict['errno']}


    def getLastLoggedInDate(self, email: str):
        sql={
            'statement': ("SELECT lastLoggedIn FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        try:
            return self.db_con.fetch(sql)
        except Exception as e:
            errorDict = e.__dict__
            return {'error':True, 'message': 'Database error!', 'code': errorDict['errno']}


    def updateLastLoggedIn(self, email: str):
        curDbDateTime = self.db_con.getCurrentDBDateTime()[0][0]
       
        sql={
            'statement': ("UPDATE users "
                            "SET lastLoggedIn = %s "
                            "WHERE email = %s"),
            'values': [curDbDateTime, email]
        }
        self.db_con.execute(sql)
            

    def userIsVerfied(self, email: str) -> bool:
        sql = {
            'statement': ("SELECT accountStatus FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        result =  self.db_con.fetch(sql)[0][0]
        if result == None or result == "Unverified":
            return False
        return True

    
    def userIsLocked(self, email :str) -> bool:
        sql = {
            'statement': ("SELECT accountStatus FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        result =  self.db_con.fetch(sql)[0][0]
        if result != "Locked":
            return False
        return True


    def deleteUser(self, email: str):
        sql = {
            'statement': ("DELETE FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        self.db_con.execute(sql)