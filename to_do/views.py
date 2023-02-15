import uuid
import jwt
from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view
from email_validator import validate_email, EmailNotValidError
from .models import User, Task
from django.contrib.auth.password_validation import validate_password, ValidationError
import bcrypt
from config import jwt_secret


def validate_token(received_token: str):
    return jwt.decode(received_token, jwt_secret, algorithms="HS256")


def validate_task(received_data: dict):
    return len(str(received_data['task_title'])) > 0


def generate_jwt_token(user_id: str) -> str:
    return jwt.encode({"user_uuid": user_id}, jwt_secret, algorithm="HS256")


def verify_password(hashed_password: str, received_password: str) -> bool:
    return bcrypt.checkpw(received_password.encode('utf-8'), hashed_password.encode('utf-8'))


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


@api_view(["POST"])
def userLogin(request):
    try:
        received_data = request.data

        fetchedUser = User.objects.filter(user_email_address=str(received_data['email_address']).strip()).values(
            'user_uuid', 'user_password')

        if fetchedUser.count() != 1:
            return JsonResponse({"error": "Email address is not registered."}, status=status.HTTP_406_NOT_ACCEPTABLE)

        if not verify_password(fetchedUser[0]['user_password'], str(received_data['password']).strip()):
            return JsonResponse({"error": "Email address and Password didn't match."},
                                status=status.HTTP_406_NOT_ACCEPTABLE)

        jsonResponse = JsonResponse({"message": "User logged in successfully!"}, status=status.HTTP_200_OK)
        jsonResponse.set_cookie(key="JWT_TOKEN", value=generate_jwt_token(fetchedUser[0]["user_uuid"]))
        return jsonResponse
    except KeyError:
        return JsonResponse({"error": "Required fields were not found."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except Exception as e:
        return JsonResponse({"errors": e.args}, status=status.HTTP_406_NOT_ACCEPTABLE)


@api_view(["POST"])
def taskCreate(request):
    try:
        received_token = request.COOKIES.get("JWT_TOKEN")
        decoded_token = validate_token(received_token)
        if User.objects.filter(user_uuid=str(decoded_token['user_uuid'])).count() < 1:
            return JsonResponse({"error": "Invalid User."}, status=status.HTTP_406_NOT_ACCEPTABLE)

        received_data = request.data
        validate_task(received_data)

        Task(task_uuid=str(uuid.uuid4()), task_title=received_data['task_title'], task_owner=User.objects.get
        (user_uuid=str(decoded_token['user_uuid']))).save()
        return JsonResponse({"message": "Task created successfully."}, status=status.HTTP_201_CREATED)
    except jwt.exceptions.DecodeError:
        return JsonResponse({"error": "User is not logged in."}, status=status.HTTP_406_NOT_ACCEPTABLE)
