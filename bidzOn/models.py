from django.db import models
from django.contrib.auth.models import AbstractUser, Permission, Group


# Create your models here.
class CustomUser(AbstractUser):
    username = None  # remove the username field

    phone_number = models.CharField(max_length=20, unique=True)
    otp = models.CharField(max_length=6)
    full_name = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    current_location = models.CharField(max_length=255, blank=True)
    destination_location = models.CharField(max_length=255, blank=True)

    USERNAME_FIELD = 'phone_number'  # use phone_number as the unique identifier
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


class Ride(models.Model):
    ride_type = models.CharField(max_length=20)
    price = models.DecimalField(max_digits=8, decimal_places=2)
    num_passengers = models.IntegerField()
    has_ac = models.BooleanField(default=False)
    ride_distance = models.DecimalField(max_digits=8, decimal_places=2)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='rides')


class Intercity(models.Model):
    ride_type = models.CharField(max_length=20)
    price = models.DecimalField(max_digits=8, decimal_places=2)
    ride_distance = models.DecimalField(max_digits=8, decimal_places=2)
    set_date = models.DateField()
    set_time = models.TimeField()
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='intercities')


class RideRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='ride_requests')
    ride = models.ForeignKey(Ride, on_delete=models.CASCADE)
    request_id = models.CharField(max_length=50)


class IntercityRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='intercity_requests')
    intercity = models.ForeignKey(Intercity, on_delete=models.CASCADE)
    request_id = models.CharField(max_length=50)
