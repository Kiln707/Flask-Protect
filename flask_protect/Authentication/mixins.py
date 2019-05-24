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

    def config_or_default(self, key):
        return (self._config[key] or self.get_defaults()[key])

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

    def get_token_status(self, token, serializer_name, max_age=None, return_data=False):
        """Get the status of a token.
        :param token: The token to check
        :param serializer: The name of the seriailzer. Can be one of the
                           following: ``confirm``, ``login``, ``reset``
        :param max_age: The name of the max age config option. Can be on of
                        the following: ``CONFIRM_EMAIL``, ``LOGIN``,
                        ``RESET_PASSWORD``
        """
        serializer = self.get_serializer(serializer_name)
        max_age = get_within_delta(max_age)
        user, data = None, None
        expired, invalid = False, False

        try:
            data = serializer.loads(token, max_age=max_age)
        except SignatureExpired:
            d, data = serializer.loads_unsafe(token)
            expired = True
        except (BadSignature, TypeError, ValueError):
            invalid = True

        if data:
            user = _datastore.find_user(id=data[0])

        expired = expired and (user is not None)

        if return_data:
            return expired, invalid, user, data
        else:
            return expired, invalid, user

    def initialize(self, app, blueprint, config, **kwargs):
        super().initialize(app, blueprint, config, **kwargs)
        for name, salt in self._config['SALT'].items():
            self.new_serializer(app, name, salt)

class UserMixin():
    pass
