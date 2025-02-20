from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    salt = models.TextField()  # зберігає сіль
    hashed_password = models.TextField()  # зберігає хеш пароля
