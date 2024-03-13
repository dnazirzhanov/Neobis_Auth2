from random import choices
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication

import jwt
from django.urls import reverse
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny

from .utils import Util
from .models import User
from neo_auth import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ObjectDoesNotExist
from django.utils.encoding import smart_bytes, smart_str, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from django.http import HttpResponseRedirect
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

from django.conf import settings
#from django.contrib.auth.models import User
from django.shortcuts import redirect
from rest_framework.permissions import AllowAny
import jwt
from django.contrib.auth import get_user_model

from rest_framework.exceptions import AuthenticationFailed, APIException
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.utils.http import urlsafe_base64_encode

from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    ProfileSerializer,
    PhoneNumberSerializer,
    CodePhoneNumberSerializer,
    UserEmailSerializer,
    EmailVerificationSerializer,
    CustomSetNewPasswordSerializer,
    CustomResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer
)
from .models import PersonalData, PhoneNumber

from django.urls import reverse_lazy


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)

        if serializer.is_valid(raise_exception=True):
            user = serializer.save()

            # Send verification email
            token = self._generate_verification_token(user)
            self._send_verification_email(user, token)

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            return Response({"user": serializer.data, "access_token": access_token}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _generate_verification_token(self, user):
        token = RefreshToken.for_user(user)
        return str(token.access_token)

    def _send_verification_email(self, user, token):
        current_site = self.request.get_host()
        verification_link = reverse_lazy("email_verify") + f"?token={token}"
        verification_url = f"http://{current_site}{verification_link}"
        body = f"Hi {user.username},\n\nPlease verify your email by clicking on the following link:\n{verification_url}"
        data = {
            "email_body": body,
            "to_email": user.email,
            "email_subject": "Verify your email",
        }
        Util.send_email(data)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            return Response({'username': user.username, 'refresh': str(refresh),
                             'access': str(refresh.access_token)}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ProfileAPIView(generics.GenericAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        user = request.user

        request.data['user'] = user.id
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        user = request.user
        personal_data = PersonalData.objects.get(user_id=user.id)
        serializer = self.serializer_class(personal_data)
        return Response(serializer.data)

    def patch(self, request):
        user = request.user
        request.data['user'] = user.id
        personal_data = PersonalData.objects.get(user_id=user.id)
        serializer = self.serializer_class(personal_data, data=request.data, partial=True)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AddPhoneNumberAPIView(generics.GenericAPIView):
    serializer_class = PhoneNumberSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        user = request.user
        request.data['user'] = user.id
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            phone_number = serializer.save()
            code_activation = '1234'
            phone_number.code_activation = code_activation
            phone_number.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        user = request.user
        phone_number = PhoneNumber.objects.get(user_id=user.id)
        serializer = self.serializer_class(phone_number)
        return Response(serializer.data)

    def put(self, request):
        user = request.user
        request.data['user'] = user.id
        phone_number = PhoneNumber.objects.get(user_id=user.id)
        serializer = self.serializer_class(phone_number, data=request.data)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivatePhoneNumberAPIView(generics.GenericAPIView):
    serializer_class = CodePhoneNumberSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        user = request.user
        code_activation_request = request.data.get('code_activation')
        code_activation_user = PhoneNumber.objects.get(user_id=user.id).code_activation
        if code_activation_request == code_activation_user:
            user.is_verified_phone = True
            user.save()
            return Response(
                {'message': 'Phone number verified successfully.'}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'message': 'Please enter the correct verification code.'}, status=status.HTTP_400_BAD_REQUEST
            )



class VerifyEmailAPIView(APIView):
    serializer_class = EmailVerificationSerializer
    permission_classes = (AllowAny,)


    def get(self, request):
        token = request.GET.get("token")
        if not token:
            return Response(
                {"error": "Token is not provided."}, status=status.HTTP_400_BAD_REQUEST
            )
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms="HS256")
            user = User.objects.get(id=payload["user_id"])
            if not user:
                return Response(
                    {"error": "User not found."}, status=status.HTTP_404_NOT_FOUND
                )
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response(
                    {"message": "Successfully activated"}, status=status.HTTP_200_OK
                )
        except jwt.ExpiredSignatureError:
            return Response(
                {"error": "Activation Expired"}, status=status.HTTP_400_BAD_REQUEST
            )
        except jwt.exceptions.DecodeError:
            return Response(
                {"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
            )


class RequestPasswordResetEmailView(APIView):
    serializer_class = CustomResetPasswordEmailRequestSerializer
    permission_classes = [AllowAny,]

    @swagger_auto_schema(
        tags=['Password Reset'],
        operation_description="Request a password reset email.",
        request_body=CustomResetPasswordEmailRequestSerializer,
        responses={
            200: "Success. Password reset email sent.",
            400: "Bad request. Invalid input data.",
            404: "User not found with the provided email address."
        }
    )

    def post(self, request):
        User = get_user_model()
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(request=request).domain
                relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
                abs_url = 'http://' + current_site + relative_link
                email_body = f'Hello,\n\nUse the link below to reset your password:\n{abs_url}'
                data = {'email_body': email_body, 'to_email': email, 'email_subject': 'Reset your password'}
                Util.send_email(data=data)
                return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    serializers = CustomSetNewPasswordSerializer
    permission_classes = [AllowAny,]

    @swagger_auto_schema(
        tags=['Password Reset'],
        operation_description="Confirm password reset.",
        manual_parameters=[
            openapi.Parameter('uidb64', openapi.IN_PATH, description="Base64-encoded user ID.",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('token', openapi.IN_PATH, description="Password reset token.", type=openapi.TYPE_STRING)
        ],
        responses={
            200: "Success. Token and uidb64 are valid.",
            400: "Bad request. Token is not valid.",
            404: "User not found with the provided ID."
        }
    )
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(id=id)


            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, try again'}, status=status.HTTP_400_BAD_REQUEST)


            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)

        except (TypeError, ValueError, OverflowError, ObjectDoesNotExist):

            return Response({'error': 'Token is not valid, try again'}, status=status.HTTP_400_BAD_REQUEST)

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    @swagger_auto_schema(
        tags=['Password Reset'],
        operation_description="Set a new password.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'password': openapi.Schema(type=openapi.TYPE_STRING, min_length=6, max_length=15),
                'token': openapi.Schema(type=openapi.TYPE_STRING, min_length=1),
                'uidb64': openapi.Schema(type=openapi.TYPE_STRING, min_length=1)
            },
            required=['password', 'token', 'uidb64']
        ),
        responses={
            200: "Success. Password reset successfully.",
            400: "Bad request. Invalid input data."
        }
    )
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
