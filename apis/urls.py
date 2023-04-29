from django.contrib import admin
from django.urls import path
from bidzOn.views import SendOTPView, VerifyOTPView, SignupView, LoginView, UpdatePasswordView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('sendotp/', SendOTPView.as_view()),
    path('verifyotp/',VerifyOTPView.as_view()),
    path('signup/', SignupView.as_view()),
    path('login/', LoginView.as_view()),
    path('forgotpassword/', UpdatePasswordView.as_view()),
]
