from builtins import object
from flask import current_app, Blueprint, url_for
from werkzeug.local import LocalProxy

class Protect(object):
    __DEFAULT_CORE_CONFIG = {
        # Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX': None,
        'SUBDOMAIN': None,
        'FLASH_MESSAGES': True,
    }

    def __init__(self, app=None, validator=None, register_blueprint=True, **kwargs):
        self.app = None
        self.validator = validator
        self._register_blueprint = register_blueprint
        self._kwargs = kwargs
        self._config = {}
        if app:
            self.init_app(app)
        else:
            self._set_core_defaults()
            self._set_core_config()

    def init_app(self, app):
        self.app = app
        self._set_core_defaults()
        self._set_core_config()
        if self._register_blueprint:
            self.blueprint = self._create_blueprint()
            app.register_blueprint(self.blueprint)
            app.context_processor(self._ctx)
        app.extensions['protect'] = self
        app.context_processor(self._ctx)

    def _create_blueprint(self):
        bp = Blueprint(self._config['BLUEPRINT_NAME'],
                    __name__,
                    url_prefix=self._config['URL_PREFIX'],
                    subdomain=self._config['SUBDOMAIN'],
                    template_folder='templates')
        if self.validator:
            self.validator.initialize_blueprint(self.app, bp)
        self._blueprint = bp
        return bp

    #
    #   Utility function
    #
    def get_config(self, key):
        if self.app:
            return self.app.config.get('PROTECT_' + key,
                self._config.get(key, self.__DEFAULT_CORE_CONFIG[key])) or self._config.get(key,
                self.__DEFAULT_CORE_CONFIG[key]) or self.__DEFAULT_CORE_CONFIG[key]
        return self._config.get(key, self.__DEFAULT_CORE_CONFIG[key]) or self.__DEFAULT_CORE_CONFIG[key]

    def url_for(self, endpoint, **kwargs):
        # Return a URL for Protect blueprint
        endpoint = '%s.%s' % (self.get_config('BLUEPRINT_NAME'), endpoint)
        return url_for(endpoint, **kwargs)

    def _ctx(self):
        return dict(url_for_protect=self.url_for, protect=LocalProxy(lambda: current_app.extensions['protect']))

    def _set_core_defaults(self):
        self._set_defaults(self.__DEFAULT_CORE_CONFIG)
        if self.validator:
            self._set_defaults(self.validator.get_defaults())

    def _set_defaults(self, values):
        for key, value in values.items():
            if self.app:
                self.app.config.setdefault('PROTECT_'+key, value)
            self._config[key] = value

    def _set_core_config(self):
        if self.app:
            self._set_config(self._get_app_defaults())
        self._set_config(self._kwargs)
        if self.validator:
            self._set_config(self.validator._kwargs)
            self.validator.initialize_config(self._config)

    def _get_app_defaults(self):
        val = {}
        for key, value in self.app.config.items():
            if key.startswith('PROTECT_'):
                val[key[len('PROTECT_'):]] = value
        return val

    def _set_config(self, values):
        for key, value in values.items():
            self._config[key] = value
