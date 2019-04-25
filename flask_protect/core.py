from builtins import object
from flask import current_app, Blueprint, url_for
from werkzeug.local import LocalProxy

class Protect(object):
    __DEFAULT_CORE_CONFIG = {
        #Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
        'URLS': {
            'LOGIN_URL':'/login',
            'LOGOUT_URL':'/logout',
            'REGISTER_URL':'/register',
            'RESET_PASS_URL':'/reset',
            'CHANGE_PASS_URL':'/change',
            'CONFIRM_EMAIL_URL':'/confirm'
            },
        'TEMPLATES': {
            'LOGIN_TEMPLATE': 'protect/login_user.html',
            'REGISTER_TEMPLATE': 'protect/register_user.html',
            'RESET_PASS_TEMPLATE': 'protect/reset_password.html',
            'FORGOT_PASS_TEMPLATE': 'protect/forgot_password.html',
            'CHANGE_PASS_TEMPLATE': 'protect/change_password.html',
            'SEND_CONFIRM_TEMPLATE': 'protect/send_confirmation.html',
        }

    }

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
            self._validator.initialize_blueprint(bp, config=self.config)
        self._blueprint=bp
        return bp

    def url_for_protect(self, endpoint, **kwargs):
        #Return a URL for Protect blueprint
        endpoint = '%s.%s' % (self.blueprint_name, endpoint)
        return url_for(endpoint, **values)

    def get_message(key, **kwargs):
        rv = self.get_config('MSGS')['MSG_' + key]
        return localize_callback(rv[0], **kwargs), rv[1]

    def set_defaults(self):
        self._set_defaults(self.__DEFAULT_CORE_CONFIG)
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
            self.config['PROTECT' + key]=value

    def get_config(self, key):
        return self.config['PROTECT'+key]
