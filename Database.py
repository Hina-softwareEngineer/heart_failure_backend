from pymongo import MongoClient
from datetime import datetime , timedelta
import os

class Database:

    def __init__(self):
        self.client = None
        self.DB = None
        self.initializeDatabase()


    def initializeDatabase(self):
        self.client = MongoClient(os.getenv('MONGODB_URI'), serverSelectionTimeoutMS=5000)
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


    def user_create_predicted_result(self, record):
        if self.DB is not None:
            return self.DB.medical_record.insert_one(record)
        return {acknowledged : False}

    def user_heart_history(self, user_id):
        if self.DB is not None:
            return self.DB.medical_record.find({'user_id' : user_id})
        return []

    def week_heart_history(self, user_id):
        lessThanDate = datetime.now()
        greaterThanDate = (datetime.now() - timedelta(days = 10))


        if self.DB is not None:
            return self.DB.medical_record.find({'user_id' : user_id, 'created_at' : { '$gte' : greaterThanDate , '$lte' : lessThanDate }})
        return None


    def __del__(self):
        print('Destructor called, Connection Closed.')

        if self.client is not None:
            self.client.close()
            self.DB = None
            print('Database connection closed.')


if __name__ == '__main__':
    DB = Database()