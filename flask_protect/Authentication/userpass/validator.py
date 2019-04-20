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

    }

    def __init__(self, datastore, crypt_context=None, **kwargs):
        self._datastore=datastore
        self._cryptcontext=None
        self._kwargs = kwargs
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

    def validate_password(self, password, hash, **kwargs):
        pass

    def validate_password_and_update_hash(self, password, hash, **kwargs):
        pass

    def dummy_validate(self):
        self._cryptcontext.dummy_verify()

    def crypt_update(**kwargs):
        self._cryptcontext.update(**kwargs)

    def initialize_blueprint(self, blueprint, **kwargs):
        super().initialize_blueprint(blueprint)
        if not self._cryptcontext:
            

    def get_defaults(self):
        return self.__DEFAULT_CONFIG

    def routes(self, blueprint):
        raise NotImplementedError()
