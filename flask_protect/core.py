from builtins import object

class Protect(object):

    def __init__(self, app=None, validator=None, register_blueprint=True, **kwargs):
        self._validator = validator
        self._register_blueprint = register_blueprint
        self._kwargs = kwargs

        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.set_defaults()

    def set_defaults(self):
        self.
