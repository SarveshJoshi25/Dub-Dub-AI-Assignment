import threading
import random
import datetime
from django.core.mail import EmailMessage
from django.http import JsonResponse
from rest_framework import status
from django.template.loader import get_template
import bcrypt
from .models import otp, User


def encrypt_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


class sendVerificationEmail(threading.Thread):
    def __init__(self, user):
        self.user = user
        threading.Thread.__init__(self)

    def run(self):
        try:
            print("Sending an request to password change email to {0} at {1}".format(self.user['user_email_address'],
                                                                                     datetime.datetime.now()))

            otp_not_encrypted = str(random.randrange(100000, 999999))

            otp.objects.filter(otp_for=self.user['user_uuid']).delete()

            otp_encrypted = encrypt_password(otp_not_encrypted)

            otp_ = otp(otp=otp_encrypted, otp_for=User.objects.get(user_uuid=self.user['user_uuid']))
            otp_.save()

            message = get_template("mail-template.html").render({
                "user_email": self.user['user_email_address'],
                "otp": otp_not_encrypted
            })

            mail = EmailMessage(
                subject="Request to change the password.",
                body=message,
                from_email="sjfrommodernconnect@gmail.com",
                to=[self.user['user_email_address']],
                reply_to=["sjfrommodernconnect@gmail.com"],
            )
            mail.content_subtype = "html"
            mail.send()
            print("Email sent successfully. at {0}".format(datetime.datetime.now()))

        except Exception as e:
            print(e)
            return JsonResponse({"error": e.args},
                                status=status.HTTP_406_NOT_ACCEPTABLE)
