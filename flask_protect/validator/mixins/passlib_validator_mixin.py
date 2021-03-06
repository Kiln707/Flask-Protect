from .validator_base import ValidatorMixin

class CryptContextValidatorMixin(ValidatorMixin):
    def __init__(self, datastore, login_manager=None, crypt_context=None, **kwargs):
        super().__init__(datastore=datastore, login_manager=login_manager, **kwargs)
        self._cryptcontext=None
        self._set_crypt_context(crypt_context)

    def hash(self, data, scheme=None, category=None, **kwargs):
        return self._cryptcontext.hash(data, scheme=scheme, category=category, **kwargs)

    def hash_password(self, password, scheme=None, category=None, **kwargs):
        return self.hash(password, scheme=None, category=None, **kwargs)

    def validate_password(self, password, hash, **kwargs):
        return self._cryptcontext.verify(password, hash, **kwargs)

    def validate_password_and_update_hash(self, password, hash, **kwargs):
        return self._cryptcontext.verify_and_update(password, hash, **kwargs)

    def dummy_validate(self):
        self._cryptcontext.dummy_verify()

    def crypt_update(**kwargs):
        self._cryptcontext.update(**kwargs)

    def _set_crypt_context(self, crypt_context):
        try:
            from passlib.context import CryptContext
            import os
        except ImportError:
            print("PassLib is not installed.")
            print("Please run 'python -m pip install passlib'")
            exit(1)
        #Take given crypt_context. determine if it should be imported
        #Or assigned. Else, Generate proper CryptContext with config
        if crypt_context and type(crypt_context) is str:
            if os.path.isfile(crypt_context):
                self._cryptcontext=CryptContext.from_path(crypt_context)
            else:
                self._cryptcontext=CryptContext.from_string(crypt_context)
        elif isinstance(crypt_context, CryptContext):
            self._cryptcontext=crypt_context

    def initialize(self, app, blueprint, **kwargs):
        super().initialize(app, blueprint, **kwargs)
        try:
            from passlib.context import CryptContext
        except ImportError:
            print("PassLib is not installed.")
            print("Please run 'python -m pip install passlib'")
            exit(1)
        if not self._cryptcontext:
            self._cryptcontext = CryptContext(**self.get_config('CRYPT_SETTINGS'))
