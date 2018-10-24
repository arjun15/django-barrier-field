"""policies_io_warrant URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib.auth.decorators import login_required
from django.urls import path

from barrier_field import views

urlpatterns = [
    path('registrera/', views.Register.as_view(), name='register'),
    path('register-complete/', views.RegistrationComplete.as_view(),
         name='registration-complete'),
    path('confirm-user/', views.ConfirmUser.as_view(),
         name='confirm-user'),
    path('update/', views.Update.as_view(), name='update'),
    path('inloggning/', views.CognitoLogIn.as_view(), name='cognito-login'),
    path('logout/', views.CognitoLogOut.as_view(), name='cognito-logout'),

    # AUTHORISED MFA SETTINGS
    path(
        'mfa-settings/',
        login_required(views.MFASettings.as_view()),
        name='mfa-settings'
    ),
    path(
        'associate-mfa/',
        login_required(views.SetSoftwareMFA.as_view()),
        name='associate-mfa'
    ),

    # MFA FORMS
    path('sms-mfa/', views.SMSMFA.as_view(), name='sms-mfa'),
    path('software-mfa/', views.SoftwareMFA.as_view(), name='software-mfa'),

    # UPDATE PASSWORD ON FORCE PASSWORD CHANGE
    path(
        'update-password/',
        views.ForceChangePassword.as_view(),
        name='force-change-password'
    ),
    path(
        'uppdatera-lösenord/',
        views.ChangePassword.as_view(),
        name='change-password'
    ),

    # FORGOT PASSWORD
    path(
        'glömt-lösenord/',
        views.ForgotPassword.as_view(),
        name='forgot-password'
    ),
    path(
        'forgot-password-sent/',
        views.ForgotPasswordSent.as_view(),
        name='forgot-password-sent'
    ),
    path(
        'återställ-lösenord/',
        views.ForgotPasswordConfirm.as_view(),
        name='forgot-password-confirm'
    ),
]
