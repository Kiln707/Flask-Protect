from itsdangerous import URLSafeTimedSerializer

from .validator_base import ValidatorMixin
from ..utils import get_within_delta

class SerializingValidatorMixin(ValidatorMixin):
    def __init__(self, datastore, login_manager=None, serializers={}, **kwargs):
        super().__init__(datastore=datastore, login_manager=login_manager, **kwargs)
        self._serializers=serializers

    def get_salt_config(self, key):
        return self.get_config('SALT')[key]

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
        if max_age:
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

    def get_defaults(self):
        defaults = {}
        print(type(self))
        if type(self) is not SerializingValidatorMixin:
            defaults = super().get_defaults().copy()
        if hasattr(self, '__DEFAULT_CONFIG'):
            return dict(ChainMap(self.__DEFAULT_CONFIG, defaults))
        if defaults:
            return defaults
        return dict()

    def initialize(self, app, blueprint, **kwargs):
        super().initialize(app, blueprint, **kwargs)
        for name, salt in self.get_config('SALT').items():
            self.create_serializer(app, name, salt)
