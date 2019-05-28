from flask import request
from ..utils import safe_url, get_within_delta

class ValidatorMixin():
    def __init__(self, datastore, login_manager, **kwargs):
        self._kwargs = kwargs
        self._datastore=datastore
        self._login_manager=login_manager
        self._config=None

    #
    #   Requires override
    #

    def login_user(self, user=None):
        raise NotImplementedError()

    def get_defaults(self):
        raise NotImplementedError()

    def routes(self, blueprint):
        raise NotImplementedError()

    def get_defaults(self):
        raise NotImplementedError()

    #
    #   Does not require override
    #

    def initialize(self, app, blueprint, config, **kwargs):
        self._config = config

    def initialize_blueprint(self, app, blueprint, config, **kwargs):
        self.initialize(app, blueprint, config, **kwargs)
        self.routes(blueprint)

    def get_and_validate_form(self, form_key):
        form = self.get_form(form_key)()
        return form, form.validate_on_submit()

    def get_url_config(self, key):
        return self.config_or_default('URLS')[key]

    def get_action_config(self, key):
        return self.config_or_default('ACTIONS')[key]

    def get_form_config(self, key):
        return self.config_or_default('FORMS')[key]

    def get_msg_config(self, key):
        return self.config_or_default('MSGS')[key]

    def get_template_config(self, key):
        return self.config_or_default('TEMPLATES')[key]

    def get_redirect_config(self, key):
        return self.config_or_default('REDIRECT')[key]

    def get_user_field(self, key):
        return self.config_or_default('USER_FIELDS')[key]

    def config_or_default(self, key):
        return (self._config[key] or self.get_defaults()[key])

class CryptContextValidatorMixin(ValidatorMixin):
    def __init__(self, datastore, login_manager, crypt_context=None, **kwargs):
        super().__init__(datastore=datastore, login_manager=login_manager, **kwargs)
        self._cryptcontext=None
        self._set_crypt_context(crypt_context)

    def hash(self, password, scheme=None, category=None, **kwargs):
        return self._cryptcontext.hash(password, scheme=scheme, category=category, **kwargs)

    def hash_password(self, password, scheme=None, category=None, **kwargs):
        return self.hash(password, scheme=None, category=None, **kwargs))

    def validate_password(self, password, hash, **kwargs):
        return self._cryptcontext.verify(password, hash, **kwargs)

    def validate_password_and_update_hash(self, password, hash, **kwargs):
        return self._cryptcontext.verify_and_update(password, hash, **kwargs)

    def dummy_validate(self):
        self._cryptcontext.dummy_verify()

    def crypt_update(**kwargs):
        self._cryptcontext.update(**kwargs)

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

    def initialize(self, app, blueprint, config, **kwargs):
        super().initialize(app, blueprint, config, **kwargs)
        if not self._cryptcontext:
            self._cryptcontext = CryptContext(**self.config_or_default('CRYPT_SETTINGS'))


class SerializingValidatorMixin(ValidatorMixin):
    def __init__(self, datastore, login_manager, serializers={}, **kwargs):
        super().__init__(datastore=datastore, login_manager=login_manager, **kwargs)
        self._serializers=serializers

    def get_salt_config(self, key):
        return self.config_or_default('SALT')[key]

    def add_serializer(self, name, serializer):
        self._serializers[name]=serializer

    def create_serializer(self, app, name, salt):
        secret_key = app.config.get('SECRET_KEY')
        self.add_serializer(name, URLSafeTimedSerializer(secret_key=secret_key, salt=salt))

    def get_serializer(self, name):
        if name in self._serializers:
            return self._serializers[name]
        return None

    def remove_serializer(self, name):
        if name in self._serializers:
            self._serializers.pop(name, None)

    def generate_token(self, serializer_name, data):
        return self.get_serializer(serializer_name).dumps(data)

    def load_token(self, token, serializer_name, max_age=None):
        serializer = self.get_serializer(serializer_name)
        max_age = get_within_delta(max_age)
        data = None
        expired, invalid = False, False
        try:
            data = serializer.loads(token, max_age=max_age)
        except SignatureExpired:
            d, data = serializer.loads_unsafe(token)
            expired = True
        except (BadSignature, TypeError, ValueError):
            invalid = True
        expired = expired and (data is not None)
        return expired, invalid, data

    def initialize(self, app, blueprint, config, **kwargs):
        super().initialize(app, blueprint, config, **kwargs)
        for name, salt in self._config['SALT'].items():
            self.new_serializer(app, name, salt)

class UserMixin():
    pass
