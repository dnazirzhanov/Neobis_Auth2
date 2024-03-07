from rest_framework import serializers
from django.contrib import auth
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from .models import User, PersonalData, PhoneNumber


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