from DBConnector import DBConnector

class UserFactory:

    def __init__(self):
        self.db_con = DBConnector()


    def createUser(self, email, name, password):
        sql = {
            'statement': ("INSERT INTO users "
                            "(email, name, password) "
                            "VALUES (%s, %s, %s)"),
            'values': (email, name, password)
        }
        self.db_con.execute(sql)
    

    def getUserByEmail(self, email):
        sql = {
            'statement': ("SELECT email, name FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        return self.db_con.fetch(sql)

    
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

    
    def deleteUser(self, email):
        sql = {
            'statement': ("DELETE FROM users "
                            "WHERE email = %s"),
            'values': [email]
        }
        self.db_con.execute(sql)
    

    