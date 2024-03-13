from rest_framework import serializers
from django.contrib import auth
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from .models import User, PersonalData, PhoneNumber
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_check = serializers.CharField(write_only=True)

    default_error_messages = {
        'password_mismatch': 'The two password fields did not match.'
    }

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_check']

    def validate(self, data):
        password = data['password']
        password_check = data['password_check']

        if password != password_check:
            raise serializers.ValidationError(
                self.default_error_messages['password_mismatch']
            )

        try:
            auth.password_validation.validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        return data

    def create(self, validated_data):
        validated_data.pop('password_check', '')
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'password']

    def validate(self, data):
        username = data.get('username', '')
        password = data.get('password', '')
        user = authenticate(username=username, password=password)
        data['user'] = user

        if not user:
            raise serializers.ValidationError('Invalid credentials, try again')

        return data


class ProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = PersonalData
        fields = ['name', 'last_name', 'photo', 'birth_date', 'email', 'username', 'user']


class PhoneNumberSerializer(serializers.ModelSerializer):

    class Meta:
        model = PhoneNumber
        fields = ['phone_number', 'user']


class CodePhoneNumberSerializer(serializers.ModelSerializer):

    class Meta:
        model = PhoneNumber
        fields = ['code_activation', 'user']


class UserEmailSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["email"]


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ["token"]


class CustomResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=8, write_only=True)

    class Meta:
        fields = ['email']

class CustomSetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return user
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid, bee', 401)
        return super().validate(attrs) # вызов родительского метода для проверрки остальных полей


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=15, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)