# vault/models.py
from django.contrib.auth.models import User
from django.db import models

class VaultEntry(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='passwords')
    encrypted_password = models.BinaryField()
    iv = models.BinaryField()
    website = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
