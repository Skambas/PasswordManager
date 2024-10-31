from rest_framework import serializers

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    hashed_password = serializers.CharField(max_length=512)
