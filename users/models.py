from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, UserManager


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=250, unique=True)
    email = models.EmailField(max_length=250, unique=True)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    objects = UserManager()


class PersonalData(models.Model):
    name = models.CharField(max_length=200, blank=False)
    last_name = models.CharField(max_length=200, blank=False)
    photo = models.ImageField(null=True, blank=True)
    birth_date = models.DateField(blank=True, null=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.last_name} {self.name}'


class PhoneNumber(models.Model):
    phone_number = models.CharField(max_length=15, blank=False, unique=True)
    code_activation = models.PositiveIntegerField(blank=True, null=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.phone_number}'