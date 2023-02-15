from django.db import models
import uuid


# Create your models here.

class User(models.Model):
    user_uuid = models.CharField(verbose_name="user_uuid", max_length=120, primary_key=True, null=False, editable=False,
                                 default=str(uuid.uuid4()))
    user_email_address = models.CharField(verbose_name="user_email_address", max_length=254, unique=True, null=False)
    user_password = models.CharField(verbose_name="user_password", max_length=365, null=False)
