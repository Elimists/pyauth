
import mysql.connector
from configparser import *
import os

class DBConnector:
    
    user = os.getenv('MY_SQL_USER')
    password = os.getenv('MY_SQL_PASSWORD')
    host = os.getenv('DB_HOST')
    database = os.getenv('DATABASE')
    raise_on_warnings = True
    mysql_connector = mysql.connector
    

   
    def __connect__(self):
        self.con = self.mysql_connector.connect(user=self.user, password=self.password, 
                                                host=self.host, database=self.database,
                                                raise_on_warnings=self.raise_on_warnings)
        self.cur = self.con.cursor()



    def __disconnect__(self):
        self.con.close()


    """
    @params The sql object that contains the sql statement and values.
    @return The result from the query operation of the db.
    """
    def fetch(self, sql):
        result = []

        if 'values' not in sql:
            self.__connect__()
            self.cur.execute(sql['statement'])
            for item in self.cur:
                result.append(item)
            self.cur.close()
            self.__disconnect__()
            return result
        else:
            self.__connect__()
            self.cur.execute(sql['statement'], sql['values'])
            for item in self.cur:
                result.append(item)
            self.cur.close()
            self.__disconnect__()
            return result


    """
    @description
    @params The sql object containing the sql statement and values.
    @return None
    """
    def execute(self, sql):
        self.__connect__()
        self.cur.execute(sql['statement'], sql['values'])
        self.con.commit()
        self.__disconnect__()

    
    def getCurrentDBDateTime(self):
        result = []
        self.__connect__()
        self.cur.execute("SELECT CURRENT_TIMESTAMP()")
        for item in self.cur:
            result.append(item)
        self.cur.close()
        self.__disconnect__()
        return result

        



