import uuid
import jwt
from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view
from email_validator import validate_email, EmailNotValidError
from .models import User, Task, otp
from django.contrib.auth.password_validation import validate_password, ValidationError
import bcrypt
from .threads import sendVerificationEmail
from config import jwt_secret


# This function starts thread, and this runs parallely with the API execution.
def send_otp(user):
    sendVerificationEmail(user).start()


# Decoding JWT token using Secret keys.
def validate_token(received_token: str):
    return jwt.decode(received_token, jwt_secret, algorithms="HS256")


# Task can be validated if Task title has length more than 0
def validate_task(received_data: dict):
    return len(str(received_data['task_title'])) > 0


# JWT Token is generated with this function.
def generate_jwt_token(user_id: str) -> str:
    return jwt.encode({"user_uuid": user_id}, jwt_secret, algorithm="HS256")


# JWT Token is generated for OTP generation format.
def generate_jwt_token_for_otp(user_id: str) -> str:
    return jwt.encode({"user_uuid": user_id, "requested": True}, jwt_secret, algorithm="HS256")


# Hashed Password and Received Password are verified.
def verify_password(hashed_password: str, received_password: str) -> bool:
    return bcrypt.checkpw(received_password.encode('utf-8'), hashed_password.encode('utf-8'))


# Password is hashed and then returned.
def generate_new_password(user_password: str) -> str:
    return bcrypt.hashpw(password=user_password.encode('utf-8'), salt=bcrypt.gensalt()).decode('utf-8')


# This function verifies if User Information entered by the User is validatable or not.
def validate_user(fetched_data: dict) -> bool:
    try:
        user_email = str(fetched_data['email_address']).strip()
        user_password = str(fetched_data['password']).strip()

        if User.objects.filter(user_email_address=user_email).count() > 0:
            raise Exception("User Email is already registered with another account.")
        # Checks if Email Address is already registered.

        validate_email(email=user_email, check_deliverability=True, globally_deliverable=True)
        validate_password(password=user_password)
        return True
    except EmailNotValidError:
        raise Exception("Invalid Email Address")
    except ValidationError:
        raise Exception("Invalid Password / Password not strong enough.")


# Testing function, This is made for StatusCake.
@api_view(["GET", "POST"])
def isAwake(request):
    return JsonResponse({"message": "The API is working fine."}, status=status.HTTP_200_OK)


# This API is for registering the user.
@api_view(["POST"])
def userRegister(request):
    """
    sample input: {
        "email_address": "contact.sarveshjoshi@gmail.com",
        "password": "YourPassword"
    }

    :param request:
    :return: Response with Status 201: for successful creation of user.
             Response with status 406: for errros.
    """
    try:
        received_data = request.data

        validate_user(received_data)

        user_id = str(uuid.uuid4())
        User(user_uuid=user_id, user_email_address=str(received_data['email_address']).strip(),
             user_password=generate_new_password(str(received_data['password']).strip())).save()
        # User details will be saved in the User table.

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
        """
            sample input: {
                "email_address": "contact.sarveshjoshi@gmail.com",
                "password": "YourPassword"
            }

            :param request:
            :return: Response with Status 200: for successful creation of log in.
                     Response with status 406: for errros.
            """
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
    """
    User has to be logged in for creating task.

    sample input: {
        "task_title": "Any Task :)"
    }

    :param request:
    :return: Response with Status 201: for successful creation of task.
             Response with status 406: for errros.
    """
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
    except KeyError:
        return JsonResponse({"error": "Required fields were not found."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except Exception as e:
        return JsonResponse({"errors": e.args}, status=status.HTTP_406_NOT_ACCEPTABLE)


@api_view(["GET"])
def taskFetch(request):
    """
    All tasks of the user are returned.

    :param request:
    :return: All tasks of particular user.
    """
    try:
        received_token = request.COOKIES.get("JWT_TOKEN")
        decoded_token = validate_token(received_token)
        user = User.objects.filter(user_uuid=str(decoded_token['user_uuid']))
        if user.count() < 1:
            return JsonResponse({"error": "Invalid User."}, status=status.HTTP_406_NOT_ACCEPTABLE)
        fetched_tasks = Task.objects.filter(task_owner=user[0].user_uuid).values()
        return JsonResponse({"tasks": list(fetched_tasks)}, status=status.HTTP_200_OK)
    except jwt.exceptions.DecodeError:
        return JsonResponse({"error": "User is not logged in."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except KeyError:
        return JsonResponse({"error": "Required fields were not found."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except Exception as e:
        return JsonResponse({"errors": e.args}, status=status.HTTP_406_NOT_ACCEPTABLE)


@api_view(["PATCH"])
def taskTick(request, task_id):
    """
    This API route is used to tick or untick a task.
    :param request:
    :param task_id:
    :return: Response with Status 200: for successful ticking of task.
             Response with status 406: for errros.
    """
    try:
        received_token = request.COOKIES.get("JWT_TOKEN")
        decoded_token = validate_token(received_token)
        task = Task.objects.filter(
            task_owner=User.objects.filter(user_uuid=str(decoded_token['user_uuid']))[0].user_uuid, task_uuid=task_id)
        if task.count() < 1:
            return JsonResponse({"error": "Task doesn't exists."}, status=status.HTTP_406_NOT_ACCEPTABLE)
        task.update(task_is_completed=not task[0].task_is_completed)
        return JsonResponse({"message": "Status updated successfully."}, status=status.HTTP_200_OK)
    except jwt.exceptions.DecodeError:
        return JsonResponse({"error": "User is not logged in."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except KeyError:
        return JsonResponse({"error": "Required fields were not found."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except Exception as e:
        return JsonResponse({"errors": e.args}, status=status.HTTP_406_NOT_ACCEPTABLE)


@api_view(["DELETE"])
def taskDelete(request, task_id):
    """
    This API route is used to delete a task.

    :param request:
    :param task_id:
    :return: Response with Status 200: for successful deletion of task.
             Response with status 406: for errros.
    """
    try:
        received_token = request.COOKIES.get("JWT_TOKEN")
        decoded_token = validate_token(received_token)
        task = Task.objects.filter(task_owner=User.objects.filter(user_uuid=str(
            decoded_token['user_uuid']))[0].user_uuid, task_uuid=task_id)
        if task.count() < 1:
            return JsonResponse({"error": "Task doesn't exists."}, status=status.HTTP_406_NOT_ACCEPTABLE)
        task.delete()
        return JsonResponse({"message": "Task deleted successfully!"}, status=status.HTTP_200_OK)
    except jwt.exceptions.DecodeError:
        return JsonResponse({"error": "User is not logged in."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except KeyError:
        return JsonResponse({"error": "Required fields were not found."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except Exception as e:
        return JsonResponse({"errors": e.args}, status=status.HTTP_406_NOT_ACCEPTABLE)


@api_view(["PATCH"])
def taskEdit(request, task_id):
    """
      This API route is used to edit a task.
      Sample Input: {
        "task_title": "Edited task"
      }

    :param request:
    :param task_id:
    :return: Response with Status 200: for successful edition of task.
             Response with status 406: for errros.
    """
    try:
        received_token = request.COOKIES.get("JWT_TOKEN")
        decoded_token = validate_token(received_token)
        task = Task.objects.filter(
            task_owner=User.objects.filter(user_uuid=str(decoded_token['user_uuid']))[0].user_uuid, task_uuid=task_id)
        if task.count() < 1:
            return JsonResponse({"error": "Task doesn't exists."}, status=status.HTTP_406_NOT_ACCEPTABLE)
        validate_task(received_data=request.data)
        task.update(task_title=request.data['task_title'])
        return JsonResponse({"message": "Task updated successfully."}, status=status.HTTP_200_OK)
    except jwt.exceptions.DecodeError:
        return JsonResponse({"error": "User is not logged in."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except KeyError:
        return JsonResponse({"error": "Required fields were not found."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except Exception as e:
        return JsonResponse({"errors": e.args}, status=status.HTTP_406_NOT_ACCEPTABLE)


@api_view(["POST"])
def resetPassword(request):
    """
    This API is used to reset password (Forgot Password).

    Sample Input : {
        "email_address": "contact.sarveshjoshi@gmail.com"
    }

    :param request:
    :return: Response with Status 200: for successful sending of otp.
             Response with status 406: for errros.\

    Password will be sent to your email address.
    """
    try:
        received_data = request.data
        user_email = str(received_data["email_address"]).strip()
        user = User.objects.filter(user_email_address=user_email).values()

        if user.count() != 1:
            return JsonResponse({"error": "Invalid request of Reset Password : User doesn't exists."},
                                status=status.HTTP_406_NOT_ACCEPTABLE)
        user_object = {"user_email_address": user[0]['user_email_address'], "user_uuid": user[0]['user_uuid']}
        send_otp(user_object)

        jsonResponse = JsonResponse({"message": "OTP was sent successfully!"}, status=status.HTTP_200_OK)

        jsonResponse.set_cookie(key="JWT_TOKEN_FOR_OTP", value=generate_jwt_token_for_otp(user[0]['user_uuid']))

        return jsonResponse
    except jwt.exceptions.DecodeError:
        return JsonResponse({"error": "User is not logged in."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except KeyError:
        return JsonResponse({"error": "Required fields were not found."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except Exception as e:
        return JsonResponse({"errors": e.args}, status=status.HTTP_406_NOT_ACCEPTABLE)


@api_view(["POST"])
def verifyPassword(request):
    """
    This API is used to reset a password.

    Sample Input: {
        "otp" : "123456",
        "password": "NewPassword"
    }
    :param request:
    :return: Response with Status 200: for successful reset of password.
             Response with status 406: for erros
    """
    try:
        decoded_token = validate_token(request.COOKIES.get('JWT_TOKEN_FOR_OTP'))
        if not decoded_token['requested']:
            return JsonResponse({"error": "Invalid request for change the password"},
                                status=status.HTTP_406_NOT_ACCEPTABLE)
        fetched_otp = otp.objects.filter(otp_for=User.objects.get(user_uuid=decoded_token['user_uuid']))

        if fetched_otp.count() != 1:
            return JsonResponse({"error": "Invalid request for change the password"},
                                status=status.HTTP_406_NOT_ACCEPTABLE)

        received_data = request.data

        received_otp = str(received_data["otp"]).strip()
        received_new_password = str(received_data["password"]).strip()

        if not verify_password(hashed_password=fetched_otp[0].otp, received_password=received_otp):
            return JsonResponse({"error": "OTP didn't match."}, status=status.HTTP_406_NOT_ACCEPTABLE)

        user = User.objects.filter(user_uuid=decoded_token['user_uuid'])
        user.update(user_password=generate_new_password(received_new_password))

        jsonResponse = JsonResponse({"message": "Request of change of password was successful."},
                                    status=status.HTTP_200_OK)
        jsonResponse.delete_cookie(key="JWT_TOKEN_FOR_OTP")
        jsonResponse.set_cookie(key="JWT_TOKEN", value=generate_jwt_token(decoded_token['user_uuid']))
        return jsonResponse

    except jwt.exceptions.DecodeError:
        return JsonResponse({"error": "User is not logged in."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except KeyError:
        return JsonResponse({"error": "Required fields were not found."}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except Exception as e:
        return JsonResponse({"errors": e.args}, status=status.HTTP_406_NOT_ACCEPTABLE)
