from ..mixins import ValidatorMixin
from passlib.context import CryptContext
import os

class UserPassValidator(ValidatorMixin):
    __DEFAULT_CONFIG={
        'ALLOW_BOTH_IDENTIFIER_AND_EMAIL'=True, #Can a identifier or email address be used for validating?
        'USE_IDENTIFIER_OR_EMAIL'='identifier', #Which field should be used if not both
        'AUTO_UPDATE_HASH'=True
        'IDENTIFIER_FIELD'='username', #Field in DB_Model for Identification
        'EMAIL_FIELD'='email',#Field in DB_Model for email
        'PASSWORD_FIELD'='password',
        'CRYPT_SETTINGS':{
            'PASSWORD_SCHEMES':[
                'bcrypt',
                'sha256_crypt',
                'sha512_crypt',
                'des_crypt',
                'pbkdf2_sha256',
                'pbkdf2_sha512',
                # And always last one...
                'plaintext'
            ],
            'DEFAULT_SCHEME': 'sha256_crypt',
            'DEPRECIATED_SCHEMES':["auto"], #By Default, Depreciate all schemes except default
            'TRUNCATE_ERROR':False, #Silently truncate password.
        }
        'MSGS': {
            'UNAUTHORIZED': (
                _('You do not have permission to view this resource.'), 'error'),
            'CONFIRM_REGISTRATION': (
                _('Thank you. Confirmation instructions '
                  'have been sent to %(email)s.'),
                'success'),
            'EMAIL_CONFIRMED': (
                _('Thank you. Your email has been confirmed.'), 'success'),
            'ALREADY_CONFIRMED': (
                _('Your email has already been confirmed.'), 'info'),
            'INVALID_CONFIRMATION_TOKEN': (
                _('Invalid confirmation token.'), 'error'),
            'EMAIL_ALREADY_ASSOCIATED': (
                _('%(email)s is already associated with an account.'), 'error'),
            'PASSWORD_MISMATCH': (
                _('Password does not match'), 'error'),
            'RETYPE_PASSWORD_MISMATCH': (
                _('Passwords do not match'), 'error'),
            'INVALID_REDIRECT': (
                _('Redirections outside the domain are forbidden'), 'error'),
            'PASSWORD_RESET_REQUEST': (
                _('Instructions to reset your password have been sent to %(email)s.'),
                'info'),
            'PASSWORD_RESET_EXPIRED': (
                _('You did not reset your password within %(within)s. '
                  'New instructions have been sent to %(email)s.'), 'error'),
            'INVALID_RESET_PASSWORD_TOKEN': (
                _('Invalid reset password token.'), 'error'),
            'CONFIRMATION_REQUIRED': (
                _('Email requires confirmation.'), 'error'),
            'CONFIRMATION_REQUEST': (
                _('Confirmation instructions have been sent to %(email)s.'), 'info'),
            'CONFIRMATION_EXPIRED': (
                _('You did not confirm your email within %(within)s. '
                  'New instructions to confirm your email have been sent '
                  'to %(email)s.'), 'error'),
            'LOGIN_EXPIRED': (
                _('You did not login within %(within)s. New instructions to login '
                  'have been sent to %(email)s.'), 'error'),
            'LOGIN_EMAIL_SENT': (
                _('Instructions to login have been sent to %(email)s.'), 'success'),
            'INVALID_LOGIN_TOKEN': (
                _('Invalid login token.'), 'error'),
            'DISABLED_ACCOUNT': (
                _('Account is disabled.'), 'error'),
            'EMAIL_NOT_PROVIDED': (
                _('Email not provided'), 'error'),
            'INVALID_EMAIL_ADDRESS': (
                _('Invalid email address'), 'error'),
            'PASSWORD_NOT_PROVIDED': (
                _('Password not provided'), 'error'),
            'PASSWORD_NOT_SET': (
                _('No password is set for this user'), 'error'),
            'PASSWORD_INVALID_LENGTH': (
                _('Password must be at least 6 characters'), 'error'),
            'USER_DOES_NOT_EXIST': (
                _('Specified user does not exist'), 'error'),
            'INVALID_PASSWORD': (
                _('Invalid password'), 'error'),
            'PASSWORDLESS_LOGIN_SUCCESSFUL': (
                _('You have successfully logged in.'), 'success'),
            'FORGOT_PASSWORD': (
                _('Forgot password?'), 'info'),
            'PASSWORD_RESET': (
                _('You successfully reset your password and you have been logged in '
                  'automatically.'), 'success'),
            'PASSWORD_IS_THE_SAME': (
                _('Your new password must be different than your previous password.'),
                'error'),
            'PASSWORD_CHANGE': (
                _('You successfully changed your password.'), 'success'),
            'LOGIN': (
                _('Please log in to access this page.'), 'info'),
            'REFRESH': (
                _('Please reauthenticate to access this page.'), 'info'),
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

    def initialize(self, config, **kwargs):
        super().initialize(config, **kwargs) #Set config
        if not self._cryptcontext:
            self._cryptcontext = CryptContext(**self._config['CRYPT_SETTINGS'])

    def get_defaults(self):
        return self.__DEFAULT_CONFIG

    def routes(self, blueprint):
        raise NotImplementedError()
