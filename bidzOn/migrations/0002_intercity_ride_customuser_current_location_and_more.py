# Generated by Django 4.2 on 2023-04-28 07:04

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('bidzOn', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Intercity',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ride_type', models.CharField(max_length=20)),
                ('price', models.DecimalField(decimal_places=2, max_digits=8)),
                ('ride_distance', models.DecimalField(decimal_places=2, max_digits=8)),
                ('set_date', models.DateField()),
                ('set_time', models.TimeField()),
            ],
        ),
        migrations.CreateModel(
            name='Ride',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ride_type', models.CharField(max_length=20)),
                ('price', models.DecimalField(decimal_places=2, max_digits=8)),
                ('num_passengers', models.IntegerField()),
                ('has_ac', models.BooleanField(default=False)),
                ('ride_distance', models.DecimalField(decimal_places=2, max_digits=8)),
            ],
        ),
        migrations.AddField(
            model_name='customuser',
            name='current_location',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='customuser',
            name='destination_location',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.CreateModel(
            name='RideRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ride_distance', models.DecimalField(decimal_places=2, max_digits=8)),
                ('request_id', models.CharField(max_length=50)),
                ('ride', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bidzOn.ride')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ride_requests', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='ride',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='rides', to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='IntercityRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ride_distance', models.DecimalField(decimal_places=2, max_digits=8)),
                ('request_id', models.CharField(max_length=50)),
                ('intercity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bidzOn.intercity')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='intercity_requests', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='intercity',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='intercities', to=settings.AUTH_USER_MODEL),
        ),
    ]
