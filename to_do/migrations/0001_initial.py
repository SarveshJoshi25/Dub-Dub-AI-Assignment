# Generated by Django 4.1.7 on 2023-02-15 06:00

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('user_uuid', models.CharField(default='5dd4eaa9-4c75-4917-8d34-83a6d3776978', editable=False, max_length=120, primary_key=True, serialize=False, verbose_name='user_uuid')),
                ('user_email_address', models.CharField(max_length=254, unique=True, verbose_name='user_email_address')),
                ('user_password', models.CharField(max_length=365, verbose_name='user_password')),
            ],
        ),
    ]
