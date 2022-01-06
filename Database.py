from config import mongoUri
from pymongo import MongoClient
import pprint

class Database:

    def __init__(self):
        self.client = None
        self.DB = None
        self.initializeDatabase()


    def initializeDatabase(self):
        self.client = MongoClient(mongoUri, serverSelectionTimeoutMS=5000)
        try:
            self.client.server_info()
            self.DB = self.client.heart_attack
            print("====================================================")
            print("Mongodb connected successfully...")
        except Exception as error:
            print("Unable to connect to the MongoDB server.", error)

    
    def get_user(self, email):
        
        if self.DB is not None:
            return self.DB.users.find_one({ "email" : email})
        return None

    def createUserInDB(self, user):
        response = self.DB.users.insert_one(user)
        return response


    def __del__(self):
        print('Destructor called, Connection Closed.')

        if self.client is not None:
            self.client.close()
            self.DB = None
            print('Database connection closed.')


if __name__ == '__main__':
    DB = Database()