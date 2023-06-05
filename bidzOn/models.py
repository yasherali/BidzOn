from django.db import models
from django.contrib.auth.models import AbstractUser, Permission, Group
from django.core.validators import FileExtensionValidator
from rest_framework.authtoken.models import Token
from django.utils.crypto import get_random_string
from django.apps import apps


# Create your models here.
class CustomUser(AbstractUser):
    username = None  # remove the username field

    phone_number = models.CharField(max_length=20)
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    full_name = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    current_location = models.CharField(max_length=255, blank=True)
    current_coordinates = models.JSONField(null=True, blank=True)
    destination_location = models.CharField(max_length=255, blank=True)
    destination_coordinates = models.JSONField(null=True, blank=True)

    USERNAME_FIELD = 'email'  # use phone_number as the unique identifier
    REQUIRED_FIELDS = ['full_name', 'city', 'password']  # add required fields

    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name='user permissions',
        blank=True,
        related_name='custom_user_permissions'  # add a unique related_name attribute
    )

    groups = models.ManyToManyField(
        Group,
        verbose_name='groups',
        blank=True,
        related_name='custom_user_groups'  # add a unique related_name attribute
    )

    def __str__(self):
        return self.phone_number


class CustomDriver(AbstractUser):
    username = None
    first_name = None
    last_name = None
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    phone_number = models.CharField(max_length=15, null=True)
    full_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=10)
    state = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    residential_address = models.TextField()
    password = models.CharField(max_length=128)
    vehicle_image = models.ImageField(upload_to='driver/vehicle_images', validators=[FileExtensionValidator(['jpg', 'jpeg', 'png'])], null=True)
    model_name = models.CharField(max_length=50, null=True)
    model_number = models.CharField(max_length=50, null=True)
    vehicle_year = models.PositiveIntegerField(null=True)
    license_plate = models.CharField(max_length=20, null=True)
    vehicle_description = models.TextField(null=True)
    select_vehicle = models.CharField(max_length=20, null=True)
    ac_heater = models.BooleanField(default=False)
    none = models.BooleanField(default=False)
    aadhar_card = models.ImageField(upload_to='driver/documents', validators=[FileExtensionValidator(['jpg', 'jpeg', 'png'])], null=True)
    pan_card = models.ImageField(upload_to='driver/documents', validators=[FileExtensionValidator(['jpg', 'jpeg', 'png'])], null=True)
    driving_license = models.ImageField(upload_to='driver/documents', validators=[FileExtensionValidator(['jpg', 'jpeg', 'png'])], null=True)
    rc_book = models.ImageField(upload_to='driver/documents', validators=[FileExtensionValidator(['jpg', 'jpeg', 'png'])], null=True)
    current_location = models.CharField(max_length=255, blank=True)
    current_coordinates = models.JSONField(null=True)
    status = models.CharField(max_length=10, default='Pending')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


class CustomDriverToken(models.Model):
    driver = models.OneToOneField(CustomDriver, on_delete=models.CASCADE)
    key = models.CharField(max_length=40, unique=True)
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Generate a unique key for the token
        if not self.key:
            self.key = self.generate_key()
        return super().save(*args, **kwargs)

    def generate_key(self):
        # Generate a unique key for the token
        return get_random_string(length=40)

    def __str__(self):
        return self.key


class RideRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='riderequest')
    RIDE_TYPE_CHOICES = (
        (0, 'Ride'),
        (1, 'Auto'),
        (2, 'Intercity')
    )
    ride_type = models.IntegerField(choices=RIDE_TYPE_CHOICES, default=0)
    entire_cabin = models.BooleanField(default=False)
    mini_cabin = models.BooleanField(default=False)
    shared_cabin = models.BooleanField(default=False)
    num_passengers = models.IntegerField()
    price = models.DecimalField(max_digits=8, decimal_places=2)
    request_id = models.CharField(max_length=50)
    ride_status = models.CharField(max_length=10, default='Pending')
    accepted_driver = models.ForeignKey(CustomDriver, on_delete=models.SET_NULL, null=True, blank=True)
    estimated_time = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    def __str__(self):
        return self.request_id


class Review(models.Model):
    driver = models.ForeignKey(CustomDriver, on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    note = models.TextField()
    rating = models.IntegerField(null=True, default=0)

    class Meta:
        unique_together = ('driver', 'user')


class Admin(models.Model):
    admin_name = models.CharField(max_length=100)
    password = models.CharField(max_length=100)


class AcceptedDriver(models.Model):
    ride_request = models.ForeignKey(RideRequest, on_delete=models.CASCADE)
    driver = models.ForeignKey(CustomDriver, on_delete=models.CASCADE, null=True)
    driver_name = models.CharField(max_length=100)
    driver_phone = models.CharField(max_length=100)
    driver_license_plate = models.CharField(max_length=100)
    driver_car_modelname = models.CharField(max_length=100, null=True)

    def __str__(self):
        return self.driver_name