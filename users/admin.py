from django.contrib import admin
from .models import User, PersonalData


admin.site.register(User)
admin.site.register(PersonalData)