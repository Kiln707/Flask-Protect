from flask import request
from ..utils import validate_redirect_url

class ValidatorMixin():
    def __init__(self, datastore, **kwargs):
        self._kwargs = kwargs
        self._datastore=datastore
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

    def initialize(self, config):
        self._config = config

    def initialize_blueprint(self, blueprint, config, **kwargs):
        self.initialize(config)
        self.routes(blueprint)

    def _get_url(endpoint_or_url):
        """Returns a URL if a valid endpoint is found. Otherwise, returns the
        provided value.
        :param endpoint_or_url: The endpoint name or URL to default to
        """
        try:
            return url_for(endpoint_or_url)
        except:
            return endpoint_or_url

    def _find_redirect(key):
        """Returns the URL to redirect to after a user logs in successfully.
        :param key: The session or application configuration key to search for
        """
        rv = (self.get_url(session.pop(key.lower(), None)) or
              self.get_url(self.config_or_default('REDIRECTS')[key] or None) or '/')
        return rv

    def get_and_validate_form(self, form_key):
        form = self.get_form(form_key)()
        return form, form.validate_on_submit()

    def get_url(self, key):
        return self.config_or_default('URLS')[key]

    def get_action(self, key):
        return self.config_or_default('ACTIONS')[key]

    def get_form(self, key):
        return self.config_or_default('FORMS')[key]

    def get_msg(self, key):
        return self.config_or_default('MSGS')[key]

    def get_template(self, key):
        return self.config_or_default('TEMPLATES')[key]

    def get_redirect(self, key, default=None):
        urls = [
            self.get_url(request.args.get('next')),
            self.get_url(request.form.get('next')),
            self._find_redirect(config_key)
        ]
        if declared:
            urls.insert(0, declared)
        for url in urls:
            if validate_redirect_url(url):
                return url

    def config_or_default(self, key):
        return (self._config[key] or self.get_defaults()[key])

class UserMixin():
    pass
