from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from .views import RegisterView, LoginView, ProfileAPIView, AddPhoneNumberAPIView, ActivatePhoneNumberAPIView, VerifyEmailAPIView, RequestPasswordResetEmailView, PasswordResetConfirmView, SetNewPasswordAPIView


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileAPIView.as_view(), name='profile'),
    path('add_phone_number/', AddPhoneNumberAPIView.as_view(), name='add_phone_number'),
    path("email_verify/", VerifyEmailAPIView.as_view(), name="email_verify"),
    path('request-reset-email/', RequestPasswordResetEmailView.as_view(), name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
    path('activate_phone_number/', ActivatePhoneNumberAPIView.as_view(), name='activate_phone_number'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]