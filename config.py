from dotenv import load_dotenv, find_dotenv
import os

load_dotenv(find_dotenv())

django_secret = os.getenv("DJANGO_SECRET")
mongo_db_connection = os.getenv("MONGODB_CONNECTION")
jwt_secret = os.getenv("JWT_SECRET")
