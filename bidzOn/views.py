import vonage
from vonage import Client, verify
from vonage.verify import Verify
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import CustomUserSerailizer, LoginSerializer
from .models import CustomUser
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model


class SendOTPView(APIView):
    def post(self, request):
        phone_number = request.data.get('phone_number')
        if not phone_number:
            return Response({"message": "Phone number is required."}, status=status.HTTP_400_BAD_REQUEST)

        client = vonage.Client(
            key=settings.VONAGE_API_KEY,
            secret=settings.VONAGE_API_SECRET
        )
        verify = vonage.Verify(client)

        response = verify.start_verification(
            number=phone_number,
            brand="BidzOn",
            workflow_id=4,
            ttl=300
        )

        if response["status"] == "0":
            request.session['request_id'] = response["request_id"]
            return Response({"message": "Verification code sent.", "phone_number": phone_number}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Failed to send verification code."}, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    def post(self, request):
        phone_number = request.data.get('phone_number')
        otp_code = request.data.get('otp_code')

        if not phone_number or not otp_code:
            return Response({"message": "Phone number and OTP code are required."}, status=status.HTTP_400_BAD_REQUEST)

        client = vonage.Client(
            key=settings.VONAGE_API_KEY,
            secret=settings.VONAGE_API_SECRET
        )
        verify = vonage.Verify(client)

        response = verify.check(
            request_id=request.session.get('request_id'),
            code=otp_code
        )

        if response["status"] == "0":
            try:
                user = CustomUser.objects.get(phone_number=phone_number)
                user.otp = otp_code
                user.save()
                return Response({"message": "OTP is verified.", "phone_number": phone_number, "otp": otp_code}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                user = CustomUser(phone_number=phone_number, otp=otp_code)
                user.save()
                return Response({"message": "OTP is verified.", "phone_number": phone_number}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Invalid verification code."}, status=status.HTTP_400_BAD_REQUEST)


class SignupView(APIView):
    def post(self, request):
        full_name = request.data.get('full_name')
        city = request.data.get('city')
        password = request.data.get('password')

        # Retrieve phone number from request data
        phone_number = request.data.get('phone_number')

        # Check if user already exists with the provided phone number
        try:
            user = CustomUser.objects.get(phone_number=phone_number)
            # If full_name is not provided, return error response
            if not full_name:
                return Response({"message": "User already exists."}, status=status.HTTP_400_BAD_REQUEST)
            # If full_name is provided, update user data and save to database
            user.full_name = full_name
            user.city = city
            user.set_password(password)
            user.save()
            # Serialize and return updated user data
            return Response({"message": "SIgnup successful", "full_name": full_name, "city": city}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            pass

        # Create new user object and save to database
        user = CustomUser(full_name=full_name, city=city, phone_number=phone_number)
        user.set_password(password)
        user.save()

        # Serialize and return user data
        serializer = CustomUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class LoginView(ObtainAuthToken):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key})

class UpdatePasswordView(APIView):
    def put(self, request):
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')

        # Check if user exists
        try:
            user = get_user_model().objects.get(phone_number=phone_number)
        except get_user_model().DoesNotExist:
            return Response({"message": "User does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        # Update password
        user.set_password(password)
        user.save()

        return Response({"message": "Password updated successfully."}, status=status.HTTP_200_OK)