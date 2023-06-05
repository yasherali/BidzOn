from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from random import randint
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework import status
from .serializers import CustomUserSerailizer, LoginSerializer, DriverReviewSerializer, CustomDriverSerializer, CustomDriverLoginSerializer
from .models import CustomUser, RideRequest, CustomDriver, Review, Admin, CustomDriverToken, AcceptedDriver
from .authentication import CustomDriverBackend
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
from decimal import Decimal
from rest_framework.parsers import MultiPartParser
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import random
import string
import threading
from geopy import distance


class RegisterAndSendOTP(APIView):
    def post(self, request):
        User = get_user_model()
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Please provide your email'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if email is already registered
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already registered'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP and save it to the user model
        otp = str(randint(100000, 999999))
        user = User(email=email, otp=otp)
        user.otp = otp
        user.save()

        # Send OTP to the user's email
        send_mail(
            'OTP Verification',
            f'Your OTP is {otp}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        return Response({'success': 'OTP has been sent to your email address.', 'email': email}, status=status.HTTP_200_OK)

class VerifyOTPAPIView(APIView):
    def post(self, request):
        User = get_user_model()
        email = request.data.get('email')
        otp = request.data.get('otp')
        if not email or not otp:
            return Response({'error': 'Please provide your email and OTP'}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, email=email)
        if user.otp != otp:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        user.otp = ''
        user.save()

        return Response({'success': 'OTP has been verified', 'email': email}, status=status.HTTP_200_OK)

class SignupView(APIView):
    def post(self, request):
        full_name = request.data.get('full_name')
        city = request.data.get('city')
        password = request.data.get('password')
        phone_number = request.data.get('phone_number')

        # Retrieve phone number from request data
        email = request.data.get('email')

        # Check if user already exists with the provided phone number
        try:
            user = CustomUser.objects.get(email=email)
            # If full_name is not provided, return error response
            if not full_name:
                return Response({"message": "User already exists."}, status=status.HTTP_400_BAD_REQUEST)
            # If full_name is provided, update user data and save to database
            user.full_name = full_name
            user.city = city
            user.phone_number = phone_number
            user.set_password(password)
            user.save()
            # Serialize and return updated user data
            return Response({"message": "SIgnup successful", "full_name": full_name, "city": city}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            pass

        # Create new user object and save to database
        user = CustomUser(full_name=full_name, city=city, email=email)
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


class SelectLocationView(APIView):
    def post(self, request):
        token_value = request.data.get('token')
        if token_value is None:
            return Response({'error': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = Token.objects.get(key=token_value)
            user = CustomUser.objects.get(id=token.user_id)
        except Token.DoesNotExist:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)

        current_location = request.data.get('current_location', None)
        current_coordinates = request.data.get('current_coordinates', None)
        destination_location = request.data.get('destination_location', None)
        destination_coordinates = request.data.get('destination_coordinates', None)

        if current_location is None or destination_location is None or current_coordinates is None or destination_coordinates is None:
            return Response({'error': 'current_location and destination_location are required fields.'},
                            status=status.HTTP_400_BAD_REQUEST)

        user.current_location = current_location
        user.current_coordinates = current_coordinates
        user.destination_location = destination_location
        user.destination_coordinates = destination_coordinates
        user.save()

        return Response({'success': 'Locations saved successfully.', 'token': token_value, 'current_location': current_location, 'destination_location': destination_location, 'current_coordinates': current_coordinates, 'destination_coordinates': destination_coordinates}, status=status.HTTP_200_OK)


@csrf_exempt
@api_view(['POST'])
def ride_request_view(request):
    # get current user based on token
    token_value = request.data.get('token')
    if token_value is None:
        return JsonResponse({'error': 'Token not provided'}, status=400)

    try:
        token = Token.objects.get(key=token_value)
        User = get_user_model()
        user = User.objects.get(id=token.user_id)
    except Token.DoesNotExist:
        return JsonResponse({'error': 'Invalid token'}, status=400)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=400)

    # get ride details from request data
    ride_type = request.data.get('ride_type')
    entire_cabin = request.data.get('entire_cabin')
    mini_cabin = request.data.get('mini_cabin')
    shared_cabin = request.data.get('shared_cabin')
    num_passengers = request.data.get('num_passengers')
    price = request.data.get('price')

    # generate a request_id
    request_id = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=10))

    # create and save ride request
    riderequest = RideRequest.objects.create(
        ride_type=ride_type,
        entire_cabin=entire_cabin,
        mini_cabin=mini_cabin,
        shared_cabin=shared_cabin,
        price=price,
        num_passengers=num_passengers,
        user=user,
        request_id=request_id
    )
    riderequest.save()

    return Response({'message': 'Ride request created successfully', 'request_id': request_id}, status=200)


@api_view(['POST'])
def get_ride_details(request):
    request_id = request.data.get('request_id')
    radius = request.data.get('radius') or 10
    if request_id is None:
        return Response({'error': 'Request ID not provided'}, status=400)

    try:
        riderequest = RideRequest.objects.get(request_id=request_id)
        user = riderequest.user
        user_location = user.current_coordinates
        if user_location is None:
            return Response({'error': 'User location not available'}, status=400)

        drivers = CustomDriver.objects.filter(current_coordinates__isnull=False)
        nearby_drivers = []
        for driver in drivers:
            driver_location = driver.current_coordinates
            if driver_location:
                driver_coords = (driver_location.get('current_coordinates'))
                user_coords = (user_location.get('current_coordinates'))
                if distance.distance(driver_coords, user_coords).km <= radius:
                    nearby_drivers.append(driver)

        ride_details = {
            'ride_type': riderequest.ride_type,
            'entire_cabin': riderequest.entire_cabin,
            'mini_cabin': riderequest.mini_cabin,
            'shared_cabin': riderequest.shared_cabin,
            'price': riderequest.price,
            'num_passengers': riderequest.num_passengers,
        }
        user_details = {
            'full_name': riderequest.user.full_name,
            'phone_number': riderequest.user.phone_number,
            'current_location': riderequest.user.current_location,
            'current_coordinates': riderequest.user.current_coordinates,
            'destination_location': riderequest.user.destination_location,
            'destination_coordinates': riderequest.user.destination_coordinates,
        }
        return Response({'ride_details': ride_details, 'user_details': user_details})
    except RideRequest.DoesNotExist:
        return Response({'error': 'Invalid Request ID'}, status=400)


@api_view(['POST'])
def create_driver(request):
    email = request.data.get('email')
    full_name = request.data.get('full_name')
    city = request.data.get('city')
    current_coordinates = request.data.get('current_coordinates')

    # check if all required fields are present
    if not email or not full_name or not city or not current_coordinates:
        return Response({'error': 'Please provide all required fields.'}, status=status.HTTP_400_BAD_REQUEST)

    # create the CustomDriver object
    driver = CustomDriver(email=email, full_name=full_name, city=city, current_coordinates=current_coordinates)

    # save the object to the database
    driver.save()

    return Response({'success': 'CustomDriver object created successfully.'}, status=status.HTTP_201_CREATED)


@csrf_exempt
@api_view(['POST'])
def find_driver(request):
    User = CustomDriver
    # get request parameters
    request_id = request.data.get('request_id')
    radius = request.data.get('radius') or 10  # default radius is 10 km

    # get user request coordinates
    user = CustomUser.objects.get(riderequest__request_id=request_id)
    user_coords = (user.current_coordinates.get('current_coordinates'))

    # find drivers within radius
    drivers = User.objects.filter(
        is_active=True,  # only active drivers
        current_coordinates__isnull=False  # only drivers with current coordinates
    )

    # filter drivers within radius
    nearby_drivers = []
    for driver in drivers:
        if driver.current_coordinates:
            driver_coords = (driver.current_coordinates.get('current_coordinates'))
            if distance.distance(driver_coords, user_coords).km <= radius:
                nearby_drivers.append(driver)

    # create response data
    response_data = {
        'nearby_drivers': [{'email': driver.email, 'full_name': driver.full_name, 'city': driver.city} for driver in nearby_drivers]
    }

    return JsonResponse(response_data)


@api_view(['POST'])
def get_driver_details(request):
    request_id = request.data.get('request_id')

    if request_id is None:
        return Response({'error': 'Request ID not provided'}, status=400)

    try:
        ride_request = RideRequest.objects.get(request_id=request_id)
    except RideRequest.DoesNotExist:
        return Response({'error': 'Invalid Request ID'}, status=400)

    accepted_drivers = AcceptedDriver.objects.filter(ride_request=ride_request)
    driver_details = []

    for accepted_driver in accepted_drivers:
        driver = accepted_driver.driver
        driver_info = {
            'email': driver.email,
            'full_name': driver.full_name,
            # Add more driver details as needed
        }
        driver_details.append(driver_info)

    response_data = {
        'request_id': request_id,
        'drivers': driver_details
    }

    return Response(response_data)

@api_view(['POST'])
def accept_ride(request):
    request_id = request.data.get('request_id')
    driver_full_name = request.data.get('driver_full_name')
    ride_status = request.data.get('ride_status')

    if not request_id or not driver_full_name or ride_status is None:
        return Response({'error': 'Incomplete parameters'}, status=400)
    try:
        ride_request = RideRequest.objects.get(request_id=request_id)
        if ride_request.ride_status == 'Accepted':  # Check if the ride request has already been accepted
            return Response({'error': 'Ride request has already been accepted'}, status=400)

        if ride_request.ride_status == 'Pending':
            driver = CustomDriver.objects.get(full_name=driver_full_name)
            ride_request.accepted_driver_id = driver.id
            ride_request.ride_status = 'Accepted'
            ride_request.save()
            # You can perform any additional actions here when the ride request is accepted

            # Retrieve the details of the accepted driver
            driver_details = {
                'email': driver.email,
                'full_name': driver.full_name,
                # Include any other driver details you want to return
            }

            return Response({'driver_details': driver_details, 'request_id': request_id})
        else:
            return Response({'error': 'Invalid ride status'}, status=400)

    except RideRequest.DoesNotExist:
        return Response({'error': 'Invalid Request ID'}, status=400)
    except CustomDriver.DoesNotExist:
        return Response({'error': 'Driver not found'}, status=400)


class TimeAndCoordinatesUpdater:
    def __init__(self, ride_request):
        self.ride_request = ride_request

    def update(self):
        driver = self.ride_request.accepted_driver

        if not driver:
            return

        driver_coordinates = driver.current_coordinates
        user_coordinates = self.ride_request.user.current_coordinates

        if not driver_coordinates or not user_coordinates:
            return

        driver_coords = (driver_coordinates.get('current_lat'), driver_coordinates.get('current_long'))
        user_coords = (user_coordinates.get('current_lat'), user_coordinates.get('current_long'))
        distance_km = distance.distance(driver_coords, user_coords).km

        average_speed = 60
        estimated_time = distance_km / average_speed

        self.ride_request.estimated_time = estimated_time
        self.ride_request.save()

        # Schedule the next update after 30 seconds
        threading.Timer(30, self.update).start()

@api_view(['POST'])
def calculate_time(request):
    request_id = request.data.get('request_id')

    if not request_id:
        return Response({'error': 'Incomplete parameters'}, status=400)

    try:
        ride_request = RideRequest.objects.get(request_id=request_id)

        if ride_request.ride_status != 'Accepted':
            return Response({'error': 'Ride request has not been accepted'}, status=400)

        updater = TimeAndCoordinatesUpdater(ride_request)

        # Start the periodic update of time and coordinates
        updater.update()

        driver = ride_request.accepted_driver

        if not driver:
            return Response({'error': 'Accepted driver not found'}, status=400)

        driver_name = driver.full_name
        driver_coordinates = driver.current_coordinates
        user_coordinates = ride_request.user.current_coordinates

        return Response({'driver_name': driver_name, 'estimated_time': ride_request.estimated_time, 'driver_coordinates': driver_coordinates, 'user_coordinates': user_coordinates})
    except RideRequest.DoesNotExist:
        return Response({'error': 'Invalid Request ID'}, status=400)


@api_view(['POST'])
def calculate_time1(request):
    request_id = request.data.get('request_id')

    if not request_id:
        return Response({'error': 'Incomplete parameters'}, status=400)

    try:
        ride_request = RideRequest.objects.get(request_id=request_id)

        if ride_request.ride_status != 'Accepted':
            return Response({'error': 'Ride request has not been accepted'}, status=400)

        driver = ride_request.accepted_driver

        if not driver:
            return Response({'error': 'Accepted driver not found'}, status=400)

        def update_time_and_coordinates():
            driver_coordinates = driver.current_coordinates
            user_coordinates = ride_request.user.current_coordinates

            if not driver_coordinates or not user_coordinates:
                return

            driver_coords = (driver_coordinates.get('current_lat'), driver_coordinates.get('current_long'))
            user_coords = (user_coordinates.get('current_lat'), user_coordinates.get('current_long'))
            distance_km = distance.distance(driver_coords, user_coords).km

            average_speed = 30  # Modify the average speed value based on the driver's expected speed

            estimated_time = (distance_km / average_speed) * 60
            estimated_time = round(estimated_time, 2)

            ride_request.estimated_time = estimated_time
            ride_request.save()

            # Schedule the next update after 30 seconds
            threading.Timer(30, update_time_and_coordinates).start()

        # Start the periodic update of time and coordinates
        update_time_and_coordinates()

        driver_name = driver.full_name
        user_name = ride_request.user.full_name
        driver_coordinates = driver.current_coordinates
        user_coordinates = ride_request.user.current_coordinates

        return Response({'user_name': user_name, 'driver_name': driver_name, 'estimated_time': ride_request.estimated_time, 'driver_coordinates': driver_coordinates, 'user_coordinates': user_coordinates})
    except RideRequest.DoesNotExist:
        return Response({'error': 'Invalid Request ID'}, status=400)


@api_view(['POST'])
def write_review(request):
    driver_full_name = request.data.get('driver_full_name')
    user_full_name = request.data.get('user_full_name')
    note = request.data.get('note')
    rating = request.data.get('rating')

    if not driver_full_name or not user_full_name or not note or rating is None:
        return Response({'error': 'Incomplete parameters'}, status=400)

    try:
        driver = CustomDriver.objects.get(full_name=driver_full_name)
        user = CustomUser.objects.get(full_name=user_full_name)

        review, created = Review.objects.get_or_create(driver=driver, user=user)
        if not created:
            return Response({'error': 'Review already exists for this driver'}, status=400)

        review.note = note
        review.rating = rating
        review.save()

        return Response({'success': 'Review saved successfully'})
    except CustomDriver.DoesNotExist:
        return Response({'error': 'Driver not found'}, status=400)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=400)


@api_view(['GET'])
def driver_reviews(request):
    driver_name = request.data.get('driver_name')

    if not driver_name:
        return Response({'error': 'Driver name parameter is required'}, status=400)

    try:
        driver = CustomDriver.objects.get(full_name=driver_name)
        serializer = DriverReviewSerializer(driver)
        return Response(serializer.data)
    except CustomDriver.DoesNotExist:
        return Response({'error': 'Driver not found'}, status=404)


@api_view(['POST'])
def verify_payment(request):
    request_id = request.data.get('request_id')
    payment = request.data.get('payment')

    if not request_id or not payment:
        return Response({'error': 'Incomplete parameters'}, status=400)

    try:
        ride_request = RideRequest.objects.get(request_id=request_id)

        if ride_request.price == Decimal(payment):
            return Response({'message': 'Payment done', 'request_id': ride_request.request_id})
        else:
            # Payment verification failed
            return Response({'error': 'Payment verification failed'}, status=400)

    except RideRequest.DoesNotExist:
        return Response({'error': 'Invalid Request ID'}, status=400)


class DriverRegisterAndSendOTP(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Please provide your email'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if email is already registered
        if CustomDriver.objects.filter(email=email).exists():
            return Response({'error': 'Email already registered'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP and save it to the driver model
        otp = str(randint(1000, 9999))
        driver = CustomDriver(email=email, otp=otp)
        driver.save()

        # Send OTP to the driver's email
        send_mail(
            'OTP Verification',
            f'Your Driver verification OTP is {otp}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        return Response({'success': 'OTP has been sent to your email address.', 'email': email}, status=status.HTTP_200_OK)


class DriverVerifyOTPAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        if not email or not otp:
            return Response({'error': 'Please provide your email and OTP'}, status=status.HTTP_400_BAD_REQUEST)

        driver = get_object_or_404(CustomDriver, email=email)
        if driver.otp != otp:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        driver.otp = ''
        driver.save()

        return Response({'success': 'OTP has been verified', 'email': email}, status=status.HTTP_200_OK)


class driverSignupView1(APIView):
    def post(self, request):
        full_name = request.data.get('full_name')
        gender = request.data.get('gender')
        state = request.data.get('state')
        city = request.data.get('city')
        residential_address = request.data.get('residential_address')
        phone_number = request.data.get('phone_number')
        email = request.data.get('email')

        try:
            driver = CustomDriver.objects.get(email=email)
            if not full_name:
                return Response({"message": "Driver already exists."}, status=status.HTTP_400_BAD_REQUEST)
            driver.full_name = full_name
            driver.gender = gender
            driver.state = state
            driver.city = city
            driver.residential_address = residential_address
            driver.phone_number = phone_number
            driver.save()
            return Response({"message": "Signup successful", "email": email,  "full_name": full_name, "city": city}, status=status.HTTP_200_OK)
        except CustomDriver.DoesNotExist:
            pass

        driver = CustomDriver(full_name=full_name, gender=gender, state=state, city=city, residential_address=residential_address, phone_number=phone_number, email=email)
        driver.save()

        return Response({"message": "Signup successful", "email": email, "full_name": full_name, "city": city}, status=status.HTTP_200_OK)


class driverSignupView2(APIView):
    parser_classes = [MultiPartParser]

    def post(self, request):
        vehicle_image = request.FILES.get('vehicle_image')
        model_name = request.data.get('model_name')
        model_number = request.data.get('model_number')
        vehicle_year = request.data.get('vehicle_year')
        license_plate = request.data.get('license_plate')
        vehicle_description = request.data.get('vehicle_description')

        if not vehicle_image or not model_name or not model_number or not vehicle_year or not license_plate or vehicle_description is None:
            return Response({'error': 'Incomplete parameters'}, status=400)

        # Retrieve email from request data
        email = request.data.get('email')

        # Check if driver already exists with the provided email
        try:
            driver = CustomDriver.objects.get(email=email)
        except CustomDriver.DoesNotExist:
            driver = CustomDriver(
                email=email,
                vehicle_image=vehicle_image,
                model_name=model_name,
                model_number=model_number,
                vehicle_year=vehicle_year,
                license_plate=license_plate,
                vehicle_description=vehicle_description
            )
            driver.save()
            return Response({"message": "Signup successful", "email": email}, status=status.HTTP_200_OK)

        # Update the existing driver's data
        driver.vehicle_image = vehicle_image
        driver.model_name = model_name
        driver.model_number = model_number
        driver.vehicle_year = vehicle_year
        driver.license_plate = license_plate
        driver.vehicle_description = vehicle_description
        driver.save()

        return Response({"message": "Driver data posted."}, status=status.HTTP_200_OK)


class driverSignupView3(APIView):
    parser_classes = [MultiPartParser]

    def post(self, request):
        select_vehicle = request.data.get('select_vehicle')
        ac_heater = request.data.get('ac_heater')
        none = request.data.get('none')
        aadhar_card = request.FILES.get('aadhar_card')
        pan_card = request.FILES.get('pan_card')
        driving_license = request.FILES.get('driving_license')
        rc_book = request.FILES.get('rc_book')
        email = request.data.get('email')

        if not select_vehicle or ac_heater not in ['true', 'false'] or none not in ['true', 'false'] or not aadhar_card or not pan_card or not driving_license or rc_book is None:
            return Response({'error': 'Incomplete parameters'}, status=400)

        try:
            driver = CustomDriver.objects.get(email=email)
        except CustomDriver.DoesNotExist:
            driver = CustomDriver(email=email)

        driver.select_vehicle = select_vehicle
        driver.ac_heater = True if ac_heater.lower() == 'true' else False
        driver.none = True if none.lower() == 'true' else False
        driver.aadhar_card = aadhar_card
        driver.pan_card = pan_card
        driver.driving_license = driving_license
        driver.rc_book = rc_book
        driver.save()

        return Response({"message": "Driver data posted.", "email": email}, status=status.HTTP_200_OK)


class CustomDriverLoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            driver = CustomDriver.objects.get(email=email)
            if driver.check_password(password):
                # Generate or retrieve the driver's token
                token, created = CustomDriverToken.objects.get_or_create(driver=driver)
                return Response({"message": "Login Successful", 'token': token.key})
        except CustomDriver.DoesNotExist:
            pass

        return Response({"message": "Invalid login credentials"}, status=status.HTTP_401_UNAUTHORIZED)


class CustomDriverLocationView(APIView):
    def post(self, request):
        token_value = request.data.get('token')
        if token_value is None:
            return Response({'error': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = CustomDriverToken.objects.get(key=token_value)
            driver = CustomDriver.objects.get(id=token.driver_id)
        except Token.DoesNotExist:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomDriver.DoesNotExist:
            return Response({'error': 'Driver not found'}, status=status.HTTP_400_BAD_REQUEST)

        current_location = request.data.get('current_location', None)
        current_coordinates = request.data.get('current_coordinates', None)

        if current_location is None or current_coordinates is None:
            return Response({'error': 'current_location and current_coordinates are required fields.'},
                            status=status.HTTP_400_BAD_REQUEST)

        driver.current_location = current_location
        driver.current_coordinates = current_coordinates
        driver.save()

        return Response(
            {'success': 'Locations saved successfully.', 'token': token_value, 'current_location': current_location, 'current_coordinates': current_coordinates}, status=status.HTTP_200_OK)


class GetRequestIDView(APIView):
    def post(self, request):
        token = request.data.get('token')
        current_coordinates = request.data.get('current_coordinates')

        driver = CustomDriverToken.objects.get(key=token)
        ride_requests = RideRequest.objects.filter(ride_status='pending')
        driver_coordinates = (float(driver.driver.current_coordinates['current_lat']), float(driver.driver.current_coordinates['current_long']))

        # Iterate over the ride requests and check if the distance is within 5km
        valid_requests = []
        for ride_request in ride_requests:
            user_coordinates = (float(ride_request.user.current_coordinates['current_lat']), float(ride_request.user.current_coordinates['current_long']))
            user_destination = (float(ride_request.user.destination_coordinates['dest_lat']), float(ride_request.user.destination_coordinates['dest_long']))
            if distance.distance(driver_coordinates, user_coordinates).km <= 5:
                pickup_distance = round(distance.distance(driver_coordinates, user_coordinates).km)
                destination_distance = round(distance.distance(driver_coordinates, user_destination).km)
                request_details = {
                    'request_id': ride_request.request_id,
                    'user_name': ride_request.user.full_name,
                    'current_location': ride_request.user.current_location,
                    'destination_location': ride_request.user.destination_location,
                    'pickup distance': pickup_distance,
                    'destination distance': destination_distance
                }
                valid_requests.append(request_details)

        # Return the list of valid request IDs
        return Response({'token': token, 'request_ids': valid_requests}, status=status.HTTP_200_OK)


class AcceptRequestView(APIView):
    def post(self, request):
        # Get the request ID and driver's token from the request data
        request_id = request.data.get('request_id')
        token = request.data.get('token')
        is_accepted = request.data.get('is_accepted')

        # Retrieve the requested ride
        try:
            ride_request = RideRequest.objects.get(request_id=request_id)
        except RideRequest.DoesNotExist:
            return Response({"message": "Invalid request ID"}, status=status.HTTP_404_NOT_FOUND)

        # Get the driver object using the token
        try:
            driver = CustomDriverToken.objects.get(key=token).driver
        except CustomDriverToken.DoesNotExist:
            return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        if is_accepted:
            # Create a new AcceptedDriver instance for the ride request
            accepted_driver = AcceptedDriver.objects.create(
                ride_request=ride_request,
                driver=driver,
                driver_name=driver.full_name,
                driver_phone=driver.phone_number,
                driver_license_plate=driver.license_plate,
                driver_car_modelname=driver.model_name,
            )
        else:
            # Remove the ride request from accepted drivers
            AcceptedDriver.objects.filter(ride_request=ride_request, driver=driver).delete()

        return Response({"message": "Request updated", "request_id": ride_request.request_id}, status=status.HTTP_200_OK)


@api_view(['GET'])
def check_request_status(request):
    # Get the driver's token from the request headers
    token = request.data.get('token')

    # Get the request ID from the request query parameters
    request_id = request.data.get('request_id')

    if not request_id:
        return Response({'error': 'Request ID not provided'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        driver = CustomDriverToken.objects.get(key=token).driver
    except CustomDriverToken.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        ride_request = RideRequest.objects.get(request_id=request_id, accepteddriver__driver=driver)
    except RideRequest.DoesNotExist:
        return Response({'message': 'Request not accepted'}, status=status.HTTP_404_NOT_FOUND)
    driver_coordinates = (
    float(driver.current_coordinates['current_lat']), float(driver.current_coordinates['current_long']))
    user_coordinates = (float(ride_request.user.current_coordinates['current_lat']),
                        float(ride_request.user.current_coordinates['current_long']))
    pickup_distance = round(distance.distance(driver_coordinates, user_coordinates).km, 2)

    # Get additional details
    accepted_driver = AcceptedDriver.objects.get(ride_request=ride_request)
    driver_details = {
        'name': accepted_driver.driver_name,
        'phone': accepted_driver.driver_phone,
        'license_plate': accepted_driver.driver_license_plate,
        'car_modelname': accepted_driver.driver_car_modelname
    }

    # Prepare the response data
    response_data = {
        'message': 'Request accepted',
        'request_id': ride_request.request_id,
        'pickup_distance': pickup_distance,
        'driver_details': driver_details,
        'current_location': ride_request.user.current_location,
        'destination_location': ride_request.user.destination_location
    }

    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['POST'])
def driver_calculate_time(request):
    request_id = request.data.get('request_id')

    if not request_id:
        return Response({'error': 'Incomplete parameters'}, status=400)

    try:
        ride_request = RideRequest.objects.get(request_id=request_id)

        if ride_request.ride_status != 'Accepted':
            return Response({'error': 'Ride request has not been accepted'}, status=400)

        driver = ride_request.accepted_driver

        if not driver:
            return Response({'error': 'Accepted driver not found'}, status=400)

        def update_time_and_coordinates():
            driver_coordinates = driver.current_coordinates
            user_coordinates = ride_request.user.current_coordinates

            if not driver_coordinates or not user_coordinates:
                return

            driver_coords = (driver_coordinates.get('current_lat'), driver_coordinates.get('current_long'))
            user_coords = (user_coordinates.get('current_lat'), user_coordinates.get('current_long'))
            distance_km = distance.distance(driver_coords, user_coords).km

            average_speed = 30  # Modify the average speed value based on the driver's expected speed

            estimated_time = (distance_km / average_speed) * 60
            estimated_time = round(estimated_time, 2)

            ride_request.estimated_time = estimated_time
            ride_request.save()

            # Schedule the next update after 30 seconds
            threading.Timer(30, update_time_and_coordinates).start()

        # Start the periodic update of time and coordinates
        update_time_and_coordinates()

        driver_name = driver.full_name
        user_name = ride_request.user.full_name
        driver_coordinates = driver.current_coordinates
        user_coordinates = ride_request.user.current_coordinates

        return Response({'user_name': user_name, 'driver_name': driver_name, 'estimated_time': ride_request.estimated_time, 'driver_coordinates': driver_coordinates, 'user_coordinates': user_coordinates})
    except RideRequest.DoesNotExist:
        return Response({'error': 'Invalid Request ID'}, status=400)


@api_view(['POST'])
def driver_destination_calculate_time(request):
    request_id = request.data.get('request_id')

    if not request_id:
        return Response({'error': 'Incomplete parameters'}, status=400)

    try:
        ride_request = RideRequest.objects.get(request_id=request_id)

        if ride_request.ride_status != 'Accepted':
            return Response({'error': 'Ride request has not been accepted'}, status=400)

        driver = ride_request.accepted_driver

        if not driver:
            return Response({'error': 'Accepted driver not found'}, status=400)

        user_coordinates = ride_request.user.current_coordinates
        destination_coordinates = ride_request.user.destination_coordinates

        if not user_coordinates or not destination_coordinates:
            return Response({'error': 'Incomplete user or destination coordinates'}, status=400)

        driver_coordinates = driver.current_coordinates

        if not driver_coordinates:
            return Response({'error': 'Driver coordinates not found'}, status=400)

        driver_coords = (driver_coordinates.get('current_lat'), driver_coordinates.get('current_long'))
        user_coords = (user_coordinates.get('current_lat'), user_coordinates.get('current_long'))
        destination_coords = (destination_coordinates.get('current_lat'), destination_coordinates.get('current_long'))
        estimated_time = distance.distance(user_coords, destination_coords).km / 80  # Adjust the average speed as per your requirement
        ride_completion = distance.distance(driver_coords, user_coords).km / (distance.distance(driver_coords, user_coords).km + distance.distance(user_coords, destination_coords).km) * 100  # Calculate the ride completion percentage
        price = ride_request.price  # Retrieve the price from the RideRequest model
        destination_location = ride_request.user.destination_location

        response_data = {
            'estimated_time': round(estimated_time, 2),
            'ride_completion': round(ride_completion, 2),
            'price': price,
            'destination location':destination_location,
        }

        return Response(response_data, status=status.HTTP_200_OK)

    except RideRequest.DoesNotExist:
        return Response({'error': 'Invalid Request ID'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def check_user_location(request):
    # Get the driver's token from the request data
    token = request.data.get('token')

    # Get the request ID from the request data
    request_id = request.data.get('request_id')

    # Get the is_located status from the request data
    is_located = request.data.get('is_located')

    if not request_id:
        return Response({'error': 'Request ID not provided'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        driver = CustomDriverToken.objects.get(key=token).driver
    except CustomDriverToken.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        ride_request = RideRequest.objects.get(request_id=request_id, accepteddriver__driver=driver)
    except RideRequest.DoesNotExist:
        return Response({'message': 'Request not accepted'}, status=status.HTTP_404_NOT_FOUND)

    if is_located == 'yes':
        # Driver has located the user
        user = ride_request.user
        response_data = {
            'request_id': ride_request.request_id,
            'located': 'yes',
            'user_full_name': user.full_name,
            'user_current_location': user.current_location,
            'user_destination_location': user.destination_location
        }
    elif is_located == 'no':
        # Driver hasn't located the user yet
        response_data = {
            'request_id': ride_request.request_id,
            'located': 'no',
            'message': 'wait'
        }
    else:
        return Response({'error': 'Invalid is_located value'}, status=status.HTTP_400_BAD_REQUEST)

    return Response(response_data, status=status.HTTP_200_OK)


class AdminView(APIView):
    def post(self, request):
        admin_name = request.data.get('admin_name')
        password = request.data.get('password')

        # Check if admin already exists with the provided admin_name
        try:
            admin = Admin.objects.get(admin_name=admin_name)
            return Response({"message": "Admin already exists."}, status=status.HTTP_400_BAD_REQUEST)
        except Admin.DoesNotExist:
            pass

        # Create new admin object and save to database
        admin = Admin(admin_name=admin_name, password=password)
        admin.save()

        return Response({"message": "Admin created successfully"}, status=status.HTTP_201_CREATED)


class AdminLoginView(APIView):
    def post(self, request):
        admin_name = request.data.get('admin_name')
        password = request.data.get('password')

        try:
            admin = Admin.objects.get(admin_name=admin_name, password=password)
        except Admin.DoesNotExist:
            return Response({"message": "Invalid admin credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({"message": "Admin login successfully", "admin_name": admin.admin_name, "admin_id": admin.id}, status=status.HTTP_200_OK)


class AdminUpdateView(APIView):
    def put(self, request):
        admin_id = 1  # Assuming there's only one admin with ID 1
        admin_name = request.data.get('admin_name')
        password = request.data.get('password')

        try:
            admin = Admin.objects.get(id=admin_id)
            admin.admin_name = admin_name
            admin.password = password
            admin.save()
        except Admin.DoesNotExist:
            return Response({"message": "Admin not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"message": "Admin updated successfully"}, status=status.HTTP_200_OK)


class PendingDriversView(APIView):
    def get(self, request):
        pending_drivers = CustomDriver.objects.filter(status='pending')
        serializer = CustomDriverSerializer(pending_drivers, many=True)
        return Response({"driver_details": serializer.data}, status=status.HTTP_200_OK)


class DriverActivationView(APIView):
    def post(self, request):
        email = request.data.get('email')

        try:
            driver = CustomDriver.objects.get(email=email, status='pending')
        except CustomDriver.DoesNotExist:
            return Response({"message": "Driver with pending status and provided email not found"}, status=status.HTTP_404_NOT_FOUND)

        # Generate a random password
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        # Validate the password
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"message": "Invalid generated password"}, status=status.HTTP_400_BAD_REQUEST)

        # Update the driver's status and save the password
        driver.status = 'activate'
        driver.set_password(password)
        driver.save()

        # Send email to the driver with their credentials
        send_mail(
            'Driver Activation',
            f'Your account has been activated.\n\nEmail: {email}\nPassword: {password}',
            'from@example.com',
            [email],
            fail_silently=False,
        )

        return Response({"message": "Driver activated and email sent", "email": email}, status=status.HTTP_200_OK)


@api_view(['GET'])
def total_users(request):
    total_users = CustomUser.objects.count()
    return Response({'total_users': total_users})


@api_view(['GET'])
def total_drivers(request):
    total_drivers = CustomDriver.objects.count()
    return Response({'total_drivers': total_drivers})


@api_view(['GET'])
def total_request_ids(request):
    total_booking = RideRequest.objects.count()
    return Response({'total_booking': total_booking})


@api_view(['GET'])
def total_model_names(request):
    model_names = CustomDriver.objects.values('model_name').distinct().count()
    return Response({'total_vehicles': model_names})


@api_view(['GET'])
def get_all_reviews(request):
    reviews = Review.objects.all()
    review_data = []

    for review in reviews:
        review_info = {
            'driver_full_name': review.driver.full_name,
            'note': review.note,
            'rating': review.rating
        }
        review_data.append(review_info)

    return Response({'reviews': review_data})


@api_view(['GET'])
def get_total_request_ids(request):
    ride_requests = RideRequest.objects.all()
    request_data = []

    for ride_request in ride_requests:
        driver_phone_number = ''
        if ride_request.accepted_driver:
            driver_phone_number = ride_request.accepted_driver.phone_number

        request_info = {
            'model_name': ride_request.accepted_driver.model_name if ride_request.accepted_driver else '',
            'user_current_location': ride_request.user.current_location,
            'user_destination_location': ride_request.user.destination_location,
            'driver_phone_number': driver_phone_number
        }
        request_data.append(request_info)

    total_request_ids = len(ride_requests)

    response_data = {
        'Routes': request_data
    }

    return Response(response_data)
