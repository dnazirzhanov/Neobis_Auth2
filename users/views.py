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

from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    ProfileSerializer,
    PhoneNumberSerializer,
    CodePhoneNumberSerializer,
    UserEmailSerializer,
    EmailVerificationSerializer
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
            # code_activation = ''.join(choices('0123456789', k=4))
            code_activation = '1234'
            phone_number.code_activation = code_activation
            phone_number.save()
            # phone_number = personal_data.phone_number
            # send_verification_code(phone_number, code_activation)
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
