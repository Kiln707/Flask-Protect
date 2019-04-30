from flask import request
from ..utils import validate_redirect_url

class ValidatorMixin():
    __DEFAULT_CONFIG={}
    def __init__(self, **kwargs):
        self._kwargs = kwargs
        self._config=None

    def get_defaults(self):
        raise NotImplementedError()

    def routes(self, blueprint):
        raise NotImplementedError()

    def initialize(self, config):
        self._config = config

    def initialize_blueprint(self, blueprint, config, **kwargs):
        self.initialize(config)
        self.routes(blueprint)

    def get_defaults(self):
        return self.__DEFAULT_CONFIG

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
        rv = (self._get_url(session.pop(key.lower(), None)) or
              self._get_url(self._config['REDIRECTS'][key] or None) or '/')
        return rv

    def get_and_validate_form(self, form_key):
        form_class = self._get_form(form_key)
        if request.is_json:
            form = form_class(MultiDict(request.get_json()))
        else:
            form = form_class(request.form)
        return form, form.validate_on_submit()

    def _get_url(self, key):
        return self._config['URLS'][key]

    def _get_form(self, key):
        return self._config['FORMS'][key]

    def _get_redirect(self, key, default=None):
        urls = [
            self._get_url(request.args.get('next')),
            self._get_url(request.form.get('next')),
            self._find_redirect(config_key)
        ]
        if declared:
            urls.insert(0, declared)
        for url in urls:
            if validate_redirect_url(url):
                return url

class UserMixin():
    pass
