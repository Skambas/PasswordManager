from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth import login as auth_login, logout as auth_logout
from .models import UserProfile
import base64


def decode_base64(data):
    """Декодуємо Base64 у байти."""
    return base64.b64decode(data)

def encode_base64(data):
    """Кодуємо байти у Base64 рядок."""
    return base64.b64encode(data).decode('utf-8')

class RegisterView(APIView):
    """Реєстрація нового користувача."""

    def get(self, request):
        """Рендеринг сторінки реєстрації."""
        return render(request, 'register.html')

    def post(self, request):
        """Обробка API-запиту на реєстрацію."""
        email = request.data.get('email')
        hashed_password = request.data.get('hashed_password')  # Очікується, що це вже Base64
        salt = request.data.get('salt')  # Очікується, що це також Base64

        if User.objects.filter(email=email).exists():
            return Response({'error': 'User with this email already exists'}, status=status.HTTP_409_CONFLICT)

        # Кодуємо хеш і сіль у Base64 перед збереженням
        encoded_hashed_password = encode_base64(decode_base64(hashed_password))
        encoded_salt = encode_base64(decode_base64(salt))

        # Створення нового користувача
        user = User.objects.create(username=email, email=email)
        user_profile = UserProfile.objects.create(
            user=user,
            hashed_password=encoded_hashed_password,
            salt=encoded_salt
        )
        user.save()
        user_profile.save()

        return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)



class LoginView(APIView):
    """Логінізація користувача."""

    def get(self, request):
        """Рендеринг сторінки логіна."""
        return render(request, 'login.html')

    def post(self, request):
        """Обробка API-запиту на логін."""
        email = request.data.get('email')
        hashed_password = request.data.get('hashed_password')

        # Декодуємо хешований пароль
        decoded_hashed_password = decode_base64(hashed_password)

        user = get_object_or_404(User, email=email)
        user_profile = get_object_or_404(UserProfile, user=user)

        # Декодуємо збережений хешований пароль
        stored_hashed_password = decode_base64(user_profile.hashed_password)

        # Перевірка хешованого пароля
        if stored_hashed_password == decoded_hashed_password:
            # Створення сесії
            auth_login(request, user)
            request.session.set_expiry(15)  # Сесія триває 15 хвилин
            return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class VaultView(APIView):
    """Сховище паролів (відображення сторінки тільки після логіну)."""

    def get(self, request):
        """Рендеринг сторінки сховища паролів."""
        if not request.user.is_authenticated:
            return redirect('login')  # Якщо користувач не залогінений, перенаправляємо на логін

        return render(request, 'vault.html')


class LogoutView(APIView):
    """Логаут користувача."""

    def post(self, request):
        auth_logout(request)
        return redirect('login')


class GetSaltView(APIView):
    """Отримання солі для користувача через API."""

    def post(self, request):
        email = request.data.get('email')

        user = get_object_or_404(User, email=email)
        user_profile = get_object_or_404(UserProfile, user=user)

        return Response({'salt': user_profile.salt}, status=status.HTTP_200_OK)
