import os

from django.conf import settings
from django.contrib import messages
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import authenticate, logout
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import (reverse, reverse_lazy)
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.generic import FormView, TemplateView
from warrant.exceptions import ForceChangePasswordException

from barrier_field import forms
from barrier_field.backend import register, complete_login, barrier_field_login
from barrier_field.client import cognito
from barrier_field.exceptions import MFARequiredSMS, MFARequiredSoftware, \
    MFAMismatch, CognitoInvalidPassword, UserNotConfirmed
from barrier_field.utils import get_user_model, generate_and_save_qr_code, \
    verify_user_email


class RegistrationComplete(TemplateView, ):
    template_name = 'barrier_field/registration_complete.html'
    title = _('Registration complete')


class ConfirmUser(TemplateView, ):
    template_name = 'barrier_field/confirm_user.html'
    title = _('Confirm User')


class CognitoLogIn(LoginView):
    form_class = forms.LoginForm

    def form_valid(self, form):
        try:
            self.request.session['login_data'] = self.request.POST
            user = authenticate(
                self.request,
                username=form.cleaned_data['username'],
                password=form.cleaned_data['password']
            )
            barrier_field_login(self.request, user)
        except ForceChangePasswordException:
            # New user must change their temporary password
            return redirect(reverse('force-change-password'))
        except MFARequiredSMS:
            return redirect(reverse('sms-mfa'))
        except MFARequiredSoftware:
            return redirect(reverse('software-mfa'))
        except UserNotConfirmed:
            return redirect(reverse('confirm-user'))
        else:
            return HttpResponseRedirect('/')


class CognitoLogOut(LogoutView):
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        username = request.user.username
        logout(request)

        if getattr(settings, 'CLEAR_USER_ON_LOGOUT', False):
            user_model = get_user_model()
            db_user = user_model.objects.get(username=username)
            db_user.delete()

        next_page = self.get_next_page()
        if next_page:
            # Redirect to this page until the session has been cleared.
            return HttpResponseRedirect(next_page)
        return super().dispatch(request, *args, **kwargs)


class Register(FormView):
    template_name = 'registration/register.html'
    form_class = forms.UserCreateForm
    #success_url = '/'
    success_url = reverse_lazy('registration-complete')

    def form_valid(self, form):
        user_model = get_user_model()
        create_user = {
            'username': form.cleaned_data['username'],
            'password': form.cleaned_data['password1'],
            'is_superuser': False,
            'is_staff': False,
            'email': form.cleaned_data['email']
        }

        # Register with cognito
        register(self.request, create_user)
        user_model.objects.create_user(**create_user)

        return super(Register, self).form_valid(form)


class Update(FormView):
    template_name = 'registration/register.html'
    form_class = forms.UserUpdateform
    success_url = '/'

    def form_valid(self, form):
        user_model = get_user_model()
        user = user_model.objects.get(username=form.cleaned_data['username'])
        update_user = {
            'is_superuser': form.cleaned_data['is_superuser'],
            'is_staff': form.cleaned_data['is_staff']
        }
        user.objects.update_user(**update_user)
        user.save()
        return super(Update, self).form_valid(form)


class ForceChangePassword(FormView):
    form_class = forms.PasswordUpdateForm
    template_name = 'barrier_field/update_cognito_password.html'

    def form_valid(self, form):
        login_form_data = self.request.session.get('login_data')
        current_password = login_form_data.get('password')
        new_password = form.cleaned_data['password1']
        try:
            # Username can drop off cognito session, if it does, add it back on
            if not cognito.username:
                cognito.username = login_form_data.get('username')
            cognito.new_password_challenge(current_password, new_password)
        except Exception as e:
            try:
                cognito.auth_error_handler(e)
            except CognitoInvalidPassword:
                error = e.response.get('Error')
                form.add_error(field='password1', error=error['Message'])
            else:
                form.add_error(
                    error=f'Code: {e["Code"]} - Message: {e["Message"]}',
                    field='password1'
                )
            return super(ForceChangePassword, self).form_invalid(form)
        else:
            verify_user_email(cognito)
            user = authenticate(
                username=cognito.username, password=new_password
            )
            barrier_field_login(self.request, user)
            return redirect('/')


class ChangePassword(FormView):
    form_class = forms.PasswordChangeForm
    template_name = 'barrier_field/change_cognito_password.html'

    def form_valid(self, form):
        current_password = form.cleaned_data['current_password']
        new_password = form.cleaned_data['new_password1']
        try:
            cognito.change_password(current_password, new_password)
        except Exception as e:
            try:
                error = e.response['Error']
            except AttributeError:
                raise AttributeError('Something went wrong there...')
            if error['Code'] == 'InvalidPasswordException':
                form.add_error(field='new_password1', error=error['Message'])
                return super(ChangePassword, self).form_invalid(form)
        else:
            return redirect(
                getattr(settings, 'PASSWORD_CHANGE_REDIRECT_URL'), '/'
            )


class SMSMFA(FormView):
    form_class = forms.MFACode
    template_name = 'barrier_field/authenticate_mfa.html'

    def get_context_data(self, **kwargs):
        context = super(SMSMFA, self).get_context_data(**kwargs)
        context['mfa_type'] = 'SMS'
        return context

    def form_valid(self, form):
        code = form.cleaned_data['mfa_code']
        username = cognito.username
        if not username:
            username = self.request.session['login_data']['username']
        response = cognito.respond_to_auth_challenge(
            'SMS_MFA', code, username,
            self.request.session.pop('MFA_CHALLENGE').get('Session')
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            complete_login(self.request, response)
        return redirect(getattr(settings, 'LOGIN_REDIRECT_URL', '/'))


class SoftwareMFA(FormView):
    form_class = forms.MFACode
    template_name = 'barrier_field/authenticate_mfa.html'

    def get_context_data(self, **kwargs):
        context = super(SoftwareMFA, self).get_context_data(**kwargs)
        context['mfa_type'] = 'Software'
        return context

    def form_valid(self, form):
        code = form.cleaned_data['mfa_code']
        username = cognito.username
        if not username:
            username = self.request.session['login_data']['username']
        try:
            response = cognito.respond_to_auth_challenge(
                'SOFTWARE_TOKEN_MFA', code, username,
                self.request.session.get('MFA_CHALLENGE').get('Session')
            )
        except Exception as e:
            try:
                cognito.auth_error_handler(e)
            except MFAMismatch:
                form.add_error(
                    field='mfa_code', error='Incorrect one time passwod'
                )
                return super(SoftwareMFA, self).form_invalid(form)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            complete_login(self.request, response)
        self.request.session.get('MFA_CHALLENGE').get('Session')
        return redirect(getattr(settings, 'LOGIN_REDIRECT_URL', '/'))


class SetSoftwareMFA(FormView):
    form_class = forms.MFACode
    template_name = 'barrier_field/associate_software_mfa.html'

    def get_context_data(self, **kwargs):
        context = super(SetSoftwareMFA, self).get_context_data(**kwargs)
        response = cognito.associate_software_token(self.request)
        secret_code = response['SecretCode']
        OTP = f'otpauth://totp/Username:{self.request.user.username}' \
            f'?secret={secret_code}&issuer=BoughtByMany'
        save_location = generate_and_save_qr_code(self. request, OTP)
        context['qr_code'] = save_location.replace('static/', '')
        context['token_code'] = secret_code
        context['mfa_type'] = 'SOFTWARE'
        return context

    def form_valid(self, form):
        # Remove temp QR code
        qr_code_loc = self.request.session['qr_code_loc']
        os.remove(qr_code_loc)

        code = form.cleaned_data['mfa_code']
        response = cognito.verify_software_token(self.request, code)
        if response['Status'] == 'SUCCESS':
            cognito.update_software_mfa(self.request, enabled=True)

        messages.success(self.request, 'Software MFA Activated')
        return redirect(reverse('mfa-settings'))


class MFASettings(FormView):
    form_class = forms.MFASettings
    template_name = 'barrier_field/mfa_settings.html'
    sms_enabled = None
    software_enabled = None

    def get_initial(self):
        user = cognito.get_user_detailed()
        mfa_preferences = user.get('UserMFASettingList')

        initial = super(MFASettings, self).get_initial()
        if not mfa_preferences:
            return initial

        if 'SOFTWARE_TOKEN_MFA' in mfa_preferences:
            self.software_enabled = True
            initial['software_mfa'] = True
        if 'SMS_MFA' in mfa_preferences:
            self.sms_enabled = True
            initial['sms_mfa'] = True

        return initial

    def form_valid(self, form):
        sms = (
            form.cleaned_data['sms_mfa'],
            self.sms_enabled
        )
        if sms[0] and not sms[1]:
            cognito.update_sms_mfa(self.request, enabled=True)
            messages.success(self.request, 'SMS MFA Activated')
        if sms[1] and not sms[0]:
            cognito.update_sms_mfa(self.request, enabled=False)
            messages.success(self.request, 'SMS MFA Deactivated')

        software = (
            form.cleaned_data['software_mfa'],
            self.software_enabled
        )
        if software[0] and not software[1]:
            return redirect(reverse('associate-mfa'))
        if software[1] and not software[0]:
            cognito.update_software_mfa(self.request, enabled=False)
            messages.success(self.request, 'Software MFA Deactivated')

        return redirect(reverse('mfa-settings'))


class ForgotPassword(FormView):
    form_class = forms.ForgotPassword
    template_name = 'barrier_field/forgot_password.html'

    def form_valid(self, form):
        email_address = form.cleaned_data['email_address']
        cognito.username = email_address
        cognito.initiate_forgot_password()
        return redirect(reverse('forgot-password-sent'))


class ForgotPasswordSent(TemplateView):
    template_name = 'barrier_field/forgot_password_sent.html'


class ForgotPasswordConfirm(FormView):
    template_name = 'barrier_field/forgot_password_confirm.html'
    form_class = forms.ForgotPasswordConfirm

    def form_valid(self, form):
        email_address = form.cleaned_data['email_address']
        verification_code = form.cleaned_data['verification_code']
        new_password = form.cleaned_data['password2']

        cognito.username = email_address
        try:
            response = cognito.confirm_forgot_password(
                verification_code, new_password
            )
        except Exception as ex:
            form.add_error(
                field='verification_code',
                error=f'Something went wrong: {ex} ->  Resp: {response}'
            )
        return redirect(reverse('cognito-login'))
