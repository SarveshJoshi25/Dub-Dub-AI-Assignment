import uuid
import jwt
from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view
from email_validator import validate_email, EmailNotValidError
from .models import User
from django.contrib.auth.password_validation import validate_password, ValidationError
import bcrypt
from config import jwt_secret


def generate_jwt_token(user_id: str) -> str:
    return jwt.encode({"user_uuid": user_id}, jwt_secret, algorithm="HS256")


# Create your views here.
def generate_new_password(user_password: str) -> str:
    return bcrypt.hashpw(password=user_password.encode('utf-8'), salt=bcrypt.gensalt()).decode('utf-8')


def validate_user(fetched_data: dict) -> bool:
    try:
        user_email = str(fetched_data['email_address']).strip()
        user_password = str(fetched_data['password']).strip()

        if User.objects.filter(user_email_address=user_email).count() > 0:
            raise Exception("User Email is already registered with another account.")

        validate_email(email=user_email, check_deliverability=True, globally_deliverable=True)
        validate_password(password=user_password)
        return True
    except EmailNotValidError:
        raise Exception("Invalid Email Address")
    except ValidationError:
        raise Exception("Invalid Password / Password not strong enough.")


@api_view(["GET", "POST"])
def isAwake(request):
    return JsonResponse({"message": "The API is working fine."}, status=status.HTTP_200_OK)


@api_view(["POST"])
def userRegister(request):
    try:
        received_data = request.data

        validate_user(received_data)

        user_id = str(uuid.uuid4())
        User(user_uuid=user_id, user_email_address=str(received_data['email_address']).strip(),
             user_password=generate_new_password(str(received_data['password']).strip())).save()

        jsonResponse = JsonResponse({"message": "Account created successfully!"}, status=status.HTTP_201_CREATED)
        jsonResponse.set_cookie(key="JWT_TOKEN", value=generate_jwt_token(user_id))
        return jsonResponse
    except KeyError:
        return JsonResponse({"error": "Required fields were not found."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except Exception as e:
        return JsonResponse({"errors": e.args}, status=status.HTTP_406_NOT_ACCEPTABLE)
