from django.db import models
import uuid


# Create your models here.

class User(models.Model):
    user_uuid = models.CharField(verbose_name="user_uuid", max_length=120, primary_key=True, null=False, editable=False,
                                 default=str(uuid.uuid4()))
    user_email_address = models.CharField(verbose_name="user_email_address", max_length=254, unique=True, null=False)
    user_password = models.CharField(verbose_name="user_password", max_length=365, null=False)


class Task(models.Model):
    task_uuid = models.CharField(verbose_name="task_uuid", max_length=120, primary_key=True, null=False, editable=False)
    task_title = models.CharField(verbose_name="task_title", max_length=120, null=False)
    task_is_completed = models.BooleanField(verbose_name="task_is_completed", default=False)
    task_owner = models.ForeignKey("User", verbose_name="task_owner", on_delete=models.CASCADE)


class otp(models.Model):
    otp = models.CharField(verbose_name="otp", max_length=120, null=False, editable=False)
    otp_for = models.ForeignKey("User", verbose_name="task_owner", on_delete=models.CASCADE)
