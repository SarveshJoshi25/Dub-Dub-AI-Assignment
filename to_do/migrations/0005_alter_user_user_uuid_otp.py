# Generated by Django 4.1.7 on 2023-02-15 11:02

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('to_do', '0004_alter_user_user_uuid_task'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='user_uuid',
            field=models.CharField(default='c9701f0e-bfeb-42cf-993c-e27e1655d588', editable=False, max_length=120, primary_key=True, serialize=False, verbose_name='user_uuid'),
        ),
        migrations.CreateModel(
            name='otp',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(editable=False, max_length=120, verbose_name='otp')),
                ('otp_for', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='to_do.user', verbose_name='task_owner')),
            ],
        ),
    ]
