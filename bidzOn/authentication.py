from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from .models import CustomDriver, CustomDriverToken


class PhoneBackend(ModelBackend):
    def authenticate(self, request, phone_number=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(phone_number=phone_number)
        except UserModel.DoesNotExist:
            return None
        else:
            if user.check_password(password):
                return user
        return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None


class CustomDriverBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        CustomDriver = get_user_model()
        try:
            user = CustomDriver.objects.get(email=email)
        except CustomDriver.DoesNotExist:
            return None
        else:
            if user.check_password(password):
                return user
        return None

    def get_user(self, user_id):
        CustomDriver = get_user_model()
        try:
            return CustomDriver.objects.get(pk=user_id)
        except CustomDriver.DoesNotExist:
            return None

    def get_driver_token(self, driver):
        try:
            driver_token = CustomDriverToken.objects.get(driver=driver)
        except CustomDriverToken.DoesNotExist:
            driver_token = CustomDriverToken.objects.create(driver=driver)
        return driver_token.token
