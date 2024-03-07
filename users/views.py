from random import choices
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    ProfileSerializer,
    PhoneNumberSerializer,
    CodePhoneNumberSerializer,
)
from .models import PersonalData, PhoneNumber


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)

        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            return Response({"user": serializer.data, "access_token": access_token}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
            user.is_verified = True
            user.save()
            return Response(
                {'message': 'Phone number verified successfully.'}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'message': 'Please enter the correct verification code.'}, status=status.HTTP_400_BAD_REQUEST
            )