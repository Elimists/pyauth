from DBConnector import DBConnector

class UserFactory:

    def __init__(self):
        self.db_con = DBConnector()


    def createUser(self, email, name, password):
        sql = {
            'statement': ("INSERT INTO users "
                            "(email, name, password, accountStatus) "
                            "VALUES (%s, %s, %s, %s)"),
            'values': (email, name, password, 'Unverified')
        }
        self.db_con.execute(sql)
    

    def getUserByEmail(self, email):
        sql = {
            'statement': ("SELECT email, name FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        return self.db_con.fetch(sql)


    def getUserPassword(self, email):
        sql = {
            'statement': ("SELECT password FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        return self.db_con.fetch(sql)

    
    def userAlreadyExistsInDB(self, email):
        sql = {
            'statement': ("SELECT email, name FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        result = self.db_con.fetch(sql)
        if not result or len(result) == 0:
            return False
        
        return True


    def updateUserName(self, email, name):
        sql = {
            'statement': ("UPDATE users "
                            "SET name = %s "
                            "WHERE email = %s"),
            'values':[name, email]
        }
        self.db_con.execute(sql)


    def updateUserPassword(self, email, password):
        sql = {
            'statement': ("UPDATE users "
                            "SET password = %s "
                            "WHERE email = %s"),
            'values': [password, email]
        }
        self.db_con.execute(sql)

    
    def updateUserAccountStatusToVerfied(self, email):
        sql = {
            'statement': ("UPDATE users "
                            "SET accountStatus = %s "
                            "WHERE email = %s"),
            'values': ["Verified", email]
        }
        self.db_con.execute(sql)


    def deleteUser(self, email):
        sql = {
            'statement': ("DELETE FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        self.db_con.execute(sql)
    

uf = UserFactory()
uf.updateUserAccountStatusToVerfied('ron.weasley@hogwarts.com')