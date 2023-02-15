from dotenv import load_dotenv, find_dotenv
import os

load_dotenv(find_dotenv())

django_secret = os.getenv("DJANGO_SECRET")
mongo_db_connection = os.getenv("MONGODB_CONNECTION")
jwt_secret = os.getenv("JWT_SECRET")
email_host_address = os.getenv("EMAIL_HOST_ADDRESS")
email_host_address_password = os.getenv("EMAIL_HOST_ADDRESS_PASSWORD")
