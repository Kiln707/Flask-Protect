from builtins import object
from flask import current_app, Blueprint, url_for
from werkzeug.local import LocalProxy

class Protect(object):

    def __init__(self, app=None, validator=None, register_blueprint=True, **kwargs):
        self._validator = validator
        self._register_blueprint = register_blueprint
        self._kwargs = kwargs
        self._config={}
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.set_defaults()
        self.set_config()
        if self._register_blueprint:
            app.register_blueprint(self.blueprint())
            app.context_processor(url_for_protect=self.url_for_protect, protect=LocalProxy(lambda: current_app.extensions['protect']))
        app.extensions['protect']=self

    def blueprint(self):
        bp = Blueprint(self._config['BLUEPRINT_NAME'], __name__,
                   url_prefix=self._config['URL_PREFIX'],
                   subdomain=self._config['SUBDOMAIN'],
                   template_folder='templates')
        if self._validator:
            self._validator.routes(bp)
        self._blueprint=bp
        return bp

    def url_for_protect(self, endpoint, **kwargs):
        #Return a URL for Protect blueprint
        endpoint = '%s.%s' % (self.blueprint_name, endpoint)
        return url_for(endpoint, **values)

    def set_defaults(self):
        from .configuration.core_config import __DEFAULT_CORE_CONFIG
        self._set_defaults(__DEFAULT_CORE_CONFIG)
        self._set_defaults(self._validator.get_defaults())

    def _set_defaults(self, values):
        for key, value in values.items():
            self.app.setdefault(key, value)

    def set_config(self):
        self._set_config(self.app.config)
        self._set_config(self.validator._kwargs)
        self._set_config(self._kwargs)

    def _set_config(self, values):
        for key, value in values.items():
            self.config[key]=value
