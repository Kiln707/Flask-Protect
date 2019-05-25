from flask import request, render_template, redirect
from .mixins import ValidatorMixin
from .forms import LoginForm, RegisterIdentifierForm, RegisterEmailForm
from .utils import _protect, _validator, get_field, get_redirect_url
from ..utils import safe_url, get_serializer, set_request_next, url_for_protect
from ..Session import FLogin_Manager
from passlib.context import CryptContext
import os

#
#   UserPass Specific methods
#
def login(form):
    user=None
    #   GET User
    #If allowing both email and username, or using email
    if _validator.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') or _validator.config_or_default('USE_EMAIL_AS_ID'):
        field = get_field(form, 'email')
        if field:
            user = _validator._datastore.get_user_by_email(field.data)
    #If allowing both email and username and user not already found by email, OR not using email
    if ( _validator.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') and not user ) or not _validator.config_or_default('USE_EMAIL_AS_ID'):
        field = get_field(form, 'identifier')
        if field:
            user = _validator._datastore.get_user_by_identifier(field.data)
    #       VALIDATE User
    if user and _validator.validate_user(user, get_field(form, 'password').data):
        _validator.login_user(user) #Valid, login user
        return True
    #Invalid username/email/identifier or password. Add error to field
    if _validator.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL'):
        get_field(form, 'identifier').errors.append(_validator.get_msg_config('BAD_USER_PASS')[0])
    elif _validator.config_or_default('USE_EMAIL_AS_ID'):
        get_field(form, 'email').errors.append(_validator.get_msg_config('BAD_EMAIL_PASS')[0])
    else:
        get_field(form, 'identifier').errors.append(_validator.get_msg_config('BAD_USER_PASS')[0])
    return False

def register(form):
    user_data = form.todict()
    user=_datastore.create_user(**userdata)
    #if confirm email address
    #generate code, and email to address
    return True

def forgot_password(form):
    # Verify account exists with given email address/Get User
    field=get_field(form, 'email')
    if field:
        user = _validator._datastore.get_user_by_email(field.data)
    # generate code to allow reset password
    if user:
        if _validator.config_or_default('FORGOT_PASS_DIRECT_TO_RESET_PASS'):
            set_request_next(url_for_protect('reset_password'))
        else:
            # Send email, with link/code to reset password, redirect
            code = _validator.generate_code(user, 'FORGOT_PASS')
            subject=_validator.config_or_default('EMAIL_SUBJECT_PASSWORD_RESET')
            recipient=user.email
            template=None
            context={}
            _validator.send_mail()
        return True
    return False

def reset_password(form):
    #   take new password, hash and update user DB with new password
    return False

def change_password(form):
    #   Check that current password is correct for user
    #   take new password, hash and update user DB with new password
    return False

def confirm_email(form):
    return False

#
#
#

class UserPassValidator(SerializingValidatorMixin, CryptContextValidatorMixin):
    __DEFAULT_CONFIG={
        'ALLOW_BOTH_IDENTIFIER_AND_EMAIL':True, #Can a identifier or email address be used for validating?
        'USE_EMAIL_AS_ID':True, #Which field should be used if not both
        'IDENTIFIER_FIELD':'username', #Field in DB_Model and form for Identification
        'EMAIL_FIELD':'email',#Field in DB_Model and form for email
        'AUTO_UPDATE_HASH':True,
        'PASSWORD_FIELD':'password',
        'LAYOUT_TEMPLATE':'protect/base.html',
        'FORGOT_PASS_DIRECT_TO_RESET_PASS':False,
        '':'',
        'EMAIL_SENDER': LocalProxy(lambda: current_app.config.get('MAIL_DEFAULT_SENDER', 'no-reply@localhost')),
        'EMAIL_SUBJECT_REGISTER': 'Welcome',
        'EMAIL_SUBJECT_CONFIRM': 'Please confirm your email',
        'EMAIL_SUBJECT_PASSWORDLESS': 'Login instructions',
        'EMAIL_SUBJECT_PASSWORD_NOTICE': 'Your password has been reset',
        'EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE': 'Your password has been changed',
        'EMAIL_SUBJECT_PASSWORD_RESET': 'Password reset instructions',
        'EMAIL_PLAINTEXT': True,
        'EMAIL_HTML': True,
        'CRYPT_SETTINGS':{
            'schemes':[
                'bcrypt',
                'sha256_crypt',
                'sha512_crypt',
                'des_crypt',
                'pbkdf2_sha256',
                'pbkdf2_sha512',
                # And always last one...
                'plaintext'
            ],
            'default': 'sha256_crypt',
            'deprecated':["auto"], #By Default, Depreciate all schemes except default
            'truncate_error':False #Silently truncate password.
            },
        'URLS': {
            'LOGIN':'/login',
            'LOGOUT':'/logout',
            'REGISTER':'/register',
            'FORGOT_PASS':'/forgot_password',
            'CHANGE_PASS':'/change',
            'CONFIRM_EMAIL':'/confirm'
            },
        'TEMPLATES': {
            'LOGIN': 'protect/form_template.html',
            'REGISTER': 'protect/form_template.html',
            'FORGOT_PASS': 'protect/form_template.html',
            'CHANGE_PASS': 'protect/form_template.html',
            'CONFIRM_EMAIL': 'protect/form_template.html',
        },
        'FORMS':{
            'LOGIN': LoginForm,
            'REGISTER': RegisterIdentifierForm,
            'FORGOT_PASS':,
            'RESET_PASS':reset_password,
            'CHANGE_PASS':None,
            'CONFIRM_EMAIL':None
            },
        'REDIRECTS':{
            'LOGIN': '',
            'LOGOUT': '',
            'REGISTER': '',
            'FORGOT_PASS': '',
            'RESET_PASS': '',
            'CHANGE_PASS': '',
            'CONFIRM_EMAIL': ''
            },
        'ACTIONS':{
            'LOGIN': login,
            'LOGOUT': None,
            'REGISTER': register,
            'FORGOT_PASS': forgot_password,
            'RESET_PASS':reset_password,
            'CHANGE_PASS': change_password,
            'CONFIRM_EMAIL': ''
        },
        'SALT':{
            'FORGOT_PASS': 'forgot-pass-salt',

            'CONFIRM_SALT': 'confirm-salt',
            'RESET_SALT': 'reset-salt',
            'LOGIN_SALT': 'login-salt',
            'CHANGE_SALT': 'change-salt',
            'REMEMBER_SALT': 'remember-salt'
        },
        'MSGS': {
            'BAD_USER_PASS':('Invalid Username or password.', 'error'),
            'BAD_EMAIL_PASS':('Invalid Email Address or Password.','error'),
            #TODO: Filter through and remove unneeded messages
            'UNAUTHORIZED': (
                ('You do not have permission to view this resource.'), 'error'),
            'CONFIRM_REGISTRATION': (
                ('Thank you. Confirmation instructions '
                  'have been sent to %(email)s.'),
                'success'),
            'EMAIL_CONFIRMED': (
                ('Thank you. Your email has been confirmed.'), 'success'),
            'ALREADY_CONFIRMED': (
                ('Your email has already been confirmed.'), 'info'),
            'INVALID_CONFIRMATION_TOKEN': (
                ('Invalid confirmation token.'), 'error'),
            'EMAIL_ALREADY_ASSOCIATED': (
                ('%(email)s is already associated with an account.'), 'error'),
            'PASSWORD_MISMATCH': (
                ('Password does not match'), 'error'),
            'RETYPE_PASSWORD_MISMATCH': (
                ('Passwords do not match'), 'error'),
            'INVALID_REDIRECT': (
                ('Redirections outside the domain are forbidden'), 'error'),
            'PASSWORD_RESET_REQUEST': (
                ('Instructions to reset your password have been sent to %(email)s.'),
                'info'),
            'PASSWORD_RESET_EXPIRED': (
                ('You did not reset your password within %(within)s. '
                  'New instructions have been sent to %(email)s.'), 'error'),
            'INVALID_RESET_PASSWORD_TOKEN': (
                ('Invalid reset password token.'), 'error'),
            'CONFIRMATION_REQUIRED': (
                ('Email requires confirmation.'), 'error'),
            'CONFIRMATION_REQUEST': (
                ('Confirmation instructions have been sent to %(email)s.'), 'info'),
            'CONFIRMATION_EXPIRED': (
                ('You did not confirm your email within %(within)s. '
                  'New instructions to confirm your email have been sent '
                  'to %(email)s.'), 'error'),
            'LOGIN_EXPIRED': (
                ('You did not login within %(within)s. New instructions to login '
                  'have been sent to %(email)s.'), 'error'),
            'LOGIN_EMAIL_SENT': (
                ('Instructions to login have been sent to %(email)s.'), 'success'),
            'INVALID_LOGIN_TOKEN': (
                ('Invalid login token.'), 'error'),
            'DISABLED_ACCOUNT': (
                ('Account is disabled.'), 'error'),
            'EMAIL_NOT_PROVIDED': (
                ('Email not provided'), 'error'),
            'INVALID_EMAIL_ADDRESS': (
                ('Invalid email address'), 'error'),
            'PASSWORD_NOT_PROVIDED': (
                ('Password not provided'), 'error'),
            'PASSWORD_NOT_SET': (
                ('No password is set for this user'), 'error'),
            'PASSWORD_INVALID_LENGTH': (
                ('Password must be at least 6 characters'), 'error'),
            'USER_DOES_NOT_EXIST': (
                ('Specified user does not exist'), 'error'),
            'INVALID_PASSWORD': (
                ('Invalid password'), 'error'),
            'PASSWORDLESS_LOGIN_SUCCESSFUL': (
                ('You have successfully logged in.'), 'success'),
            'FORGOT_PASSWORD': (
                ('Forgot password?'), 'info'),
            'PASSWORD_RESET': (
                ('You successfully reset your password and you have been logged in '
                  'automatically.'), 'success'),
            'PASSWORD_IS_THE_SAME': (
                ('Your new password must be different than your previous password.'),
                'error'),
            'PASSWORD_CHANGE': (
                ('You successfully changed your password.'), 'success'),
            'LOGIN': (
                ('Please log in to access this page.'), 'info'),
            'REFRESH': (
                ('Please reauthenticate to access this page.'), 'info')
        },
        'FORM_FIELDS':{
            'identifier':'Username',
            'email':'Email Address',
            'password':'Password',
            'remember_me':'Remember Me',
            'login':'Login',
            'register':'Register'
        },
        'USER_FIELDS':{
            'identifier':'username',
            'email':'email_address',
            'password':'password'
        }
    }

    def __init__(self, datastore, login_manager, crypt_context=None, **kwargs):
        super().__init__(datastore=datastore, login_manager=login_manager, crypt_context=crypt_context, **kwargs)

    #
    #   Validator Functions
    #
    def validate_user(self, identifier, password, **kwargs):
        if isinstance(identifier, self._datastore.UserModel):
            user = identifier
        else:
            user = self._datastore.get_user(identifier)
        valid=False
        newhash=None
        if user:
            if self.config_or_default('AUTO_UPDATE_HASH'):
                valid, newhash = self.validate_password_and_update_hash(password, user.password, **kwargs)
            else:
                valid = self.validate_password(password, user.password, **kwargs)
            if valid and newhash:
                self._datastore.update_password_hash(user, newhash)
        else:
            self.dummy_verify()
        return valid

    def login_user(self, user, remember=False, duration=None, force=False, fresh=True):
        self._login_manager.login_user(user=user, remember=remember, duration=duration, force=force, fresh=fresh)

    def logout_user(self):
        self._login_manager.logout_user()

    #
    #   Other Utilites
    #
    def generate_code(self, user, action):
        password_hash = self.hash(user.password) if user.password else None
        data = [str(user.id), password_hash]
        return self.generate_token(self, action, data)

    def send_mail(self, subject, recipient, template, **context):
        pass

    #
    #   View Methods
    #
    def view(self, action):
        form, validated = self.get_and_validate_form(action)
        if validated:
            action_func = self.get_action_config(action)
            if action_func(form):
                redirect_url = get_redirect_url(self.get_redirect_config(action))
                return redirect(redirect_url)
        template = self.get_template_config(action)
        return render_template(template, layout=self.config_or_default('LAYOUT_TEMPLATE'), form=form)

    def login_view(self):
        return self.view('LOGIN')

    def register_view(self):
        return self.view('REGISTER')

    def forgot_pass_view(self):
        return self.view('FORGOT_PASS')

    def change_pass_view(self):
        return self.view('CHANGE_PASS')

    def logout_view(self):
        action_func = self.get_action_config(action)
        if action_func:
            action_func()
        self.logout_user()
        redirect_url = get_redirect_url(self.get_redirect_config(action))
        return redirect(redirect_url)

    def reset_pass_view(self, reset_code):
        #If valid code for forgotten password:
        return self.view('RESET_PASS')
        #else, ERROR!

    def confirm_email_view(self, confirm_code):
        pass

    #
    #   Blueprint Section
    #
    def routes(self, blueprint):
        blueprint.add_url_rule(rule=self.get_url_config('LOGIN'), endpoint='login', view_func=self.login_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('REGISTER'), endpoint='register', view_func=self.register_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('LOGOUT'), endpoint='logout', view_func=self.logout_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('FORGOT_PASS'), endpoint='forgot_password', view_func=self.forgot_pass_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('RESET_PASS'), endpoint='reset_password', view_func=self.reset_pass_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('CHANGE_PASS'), endpoint='change_password', view_func=self.change_pass_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('CONFIRM_EMAIL'), endpoint='confirm_email', view_func=self.confirm_email_view, methods=['GET', 'POST'])

    def get_defaults(self):
        return self.__DEFAULT_CONFIG
