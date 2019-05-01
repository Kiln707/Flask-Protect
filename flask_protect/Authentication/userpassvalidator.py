from flask import request, render_template
from .mixins import ValidatorMixin
from .forms import LoginForm
from .utils import _validator
from passlib.context import CryptContext
import os

#
#   UserPass Specific methods
#

def login(form):
    def get_field(form, key):
        return getattr(form, _validator.config_or_default('field_labels')[key])
    user=None
    #If allowing both email and username, or using email
    if _validator.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') or _validator.config_or_default('USE_EMAIL_AS_ID'):
        user = _validator._datastore.get_user_by_email(get_field(form, 'email').data)
    #If allowing both email and username and user not already found by email, OR not using email
    if ( _validator.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') and not user ) or not _validator.config_or_default('USE_EMAIL_AS_ID'):
        user = _validator._datastore.get_user_by_identifier(get_field(form, 'identifier').data)
    #Valid user?
    if _validator.validate_user(user, get_field('password').data):
        _validator.login_user(user) #Valid, login user
        return True
    #Invalid username/email/identifier or password. Add error to field
    if _validator.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL'):
        get_field(form, 'identifier').errors.append(_validator.config_or_default())
    elif _validator.config_or_default('USE_EMAIL_AS_ID'):
        get_field(form, 'email').errors.append()
    else:
        get_field(form, 'identifier').errors.append()
    return False

#
#
#

class UserPassValidator(ValidatorMixin):
    __DEFAULT_CONFIG={
        'ALLOW_BOTH_IDENTIFIER_AND_EMAIL':True, #Can a identifier or email address be used for validating?
        'USE_EMAIL_AS_ID':True, #Which field should be used if not both
        'IDENTIFIER_FIELD':'username', #Field in DB_Model for Identification
        'EMAIL_FIELD':'email',#Field in DB_Model for email
        'AUTO_UPDATE_HASH':True,
        'PASSWORD_FIELD':'password',
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
            'RESET_PASS':'/reset',
            'CHANGE_PASS':'/change',
            'CONFIRM_EMAIL':'/confirm'
            },
        'TEMPLATES': {
            'LOGIN': 'protect/form_template.html',
            'REGISTER': 'protect/register_user.html',
            'RESET_PASS': 'protect/reset_password.html',
            'CHANGE_PASS': 'protect/change_password.html',
            'CONFIRM_EMAIL': 'protect/send_confirmation.html',
        },
        'FORMS':{
            'LOGIN': LoginForm,
            'LOGOUT': None,
            'REGISTER': None,
            'RESET_PASS':None,
            'CHANGE_PASS':None,
            'CONFIRM_EMAIL':None
            },
        'REDIRECTS':{
            'LOGIN': '',
            'LOGOUT': '',
            'REGISTER': '',
            'RESET_PASS': '',
            'CHANGE_PASS': '',
            'CONFIRM_EMAIL': ''
            },
        'ACTIONS':{
            'LOGIN': login,
            'LOGOUT': '',
            'REGISTER': '',
            'RESET_PASS': '',
            'CHANGE_PASS': '',
            'CONFIRM_EMAIL': ''
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

    def __init__(self, datastore, crypt_context=None, **kwargs):
        super().__init__(**kwargs)
        self._datastore=datastore
        self._cryptcontext=None
        self._set_crypt_context(crypt_context)

    def _set_crypt_context(self, crypt_context):
        #Take given crypt_context. determine if it should be imported
        #Or assigned. Else, Generate proper CryptContext with config
        if crypt_context and type(crypt_context) is str:
            if os.path.isfile(crypt_context):
                self._cryptcontext=CryptContext.from_path(crypt_context)
            else:
                self._cryptcontext=CryptContext.from_string(crypt_context)
        elif isinstance(crypt_context, CryptContext):
            self._cryptcontext=crypt_context

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
            if self.config['AUTO_UPDATE_HASH']:
                valid, newhash = self.validate_password_and_update_hash(password, user.password, **kwargs)
            else:
                valid = self.validate_password(password, user.password, **kwargs)
            if valid and newhash:
                self._datastore.update_password_hash(user, newhash)
        else:
            self.dummy_verify()
        return valid

    def hash_password(self, password, scheme=None, category=None, **kwargs):
        return self._cryptcontext.hash(self, password, scheme=scheme, category=category, **kwargs)

    def validate_password(self, password, hash, **kwargs):
        return self._cryptcontext.verify(password, hash, **kwargs)

    def validate_password_and_update_hash(self, password, hash, **kwargs):
        return self._cryptcontext.verify_and_update()

    def dummy_validate(self):
        self._cryptcontext.dummy_verify()

    def crypt_update(**kwargs):
        self._cryptcontext.update(**kwargs)

    #
    #   View Methods
    #

    def login_view(self):
        form, validated = self.get_and_validate_form('LOGIN')
        if validated:
            login = self.config('ACTIONS')['LOGIN']
            if login(form):
                return redirect(self.config_or_default('REDIRECTS')['LOGIN'])
        template = self.config_or_default('TEMPLATES')['LOGIN']
        print(template, form)
        return render_template(template)

    #
    #   Blueprint Section
    #

    def routes(self, blueprint):
        blueprint.add_url_rule(rule=self._get_url('LOGIN'), endpoint='login', view_func=self.login_view, methods=['GET', 'POST'])

    def initialize(self, config, **kwargs):
        super().initialize(config, **kwargs) #Set config
        if not self._cryptcontext:
            self._cryptcontext = CryptContext(**self.config('CRYPT_SETTINGS', default=self.__DEFAULT_CONFIG['CRYPT_SETTINGS']))

    def get_defaults(self):
        return self.__DEFAULT_CONFIG

    def config_or_default(self, key):
        return (self.config(key, default=self.__DEFAULT_CONFIG[key]))
