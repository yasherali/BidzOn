from rest_framework import serializers
from .models import CustomUser, CustomDriver, Review
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token


class CustomUserSerailizer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'otp', 'phone_number', 'full_name', 'city', 'current_location', 'destination_location', 'password']


class LoginSerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        phone_number = attrs.get('phone_number')
        password = attrs.get('password')

        if phone_number and password:
            user = authenticate(request=self.context.get('request'), phone_number=phone_number, password=password)
            if not user:
                msg = ('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "phone_number" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs


class CustomDriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomDriver
        fields = ('email', 'full_name', 'phone_number', 'gender', 'state', 'city', 'residential_address', 'model_name', 'model_number', 'vehicle_year', 'license_plate', 'nic', 'driving_license', 'status')


class ReviewSerializer(serializers.ModelSerializer):
    user_full_name = serializers.SerializerMethodField()

    def get_user_full_name(self, obj):
        return obj.user.full_name

    class Meta:
        model = Review
        fields = ['user_full_name', 'note', 'rating']


class DriverReviewSerializer(serializers.ModelSerializer):
    reviews = ReviewSerializer(many=True, read_only=True)

    class Meta:
        model = CustomDriver
        fields = ['full_name', 'reviews']


class CustomDriverLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        try:
            driver = CustomDriver.objects.get(email=email)
        except CustomDriver.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password")

        if not driver.check_password(password):
            raise serializers.ValidationError("Invalid email or password")

        attrs['driver'] = driver
        return attrs

    def create(self, validated_data):
        driver = validated_data['driver']
        token, _ = Token.objects.get_or_create(user=driver.user)
        driver.token = token
        driver.save()
        data['token'] = token.key
        return data
