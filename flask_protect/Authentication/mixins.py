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
        rv = (self._get_url(session.pop(key.lower(), None)) or
              self._get_url(self.config_or_default('REDIRECTS')[key] or None) or '/')
        return rv

    def get_and_validate_form(self, form_key):
        form = self._get_form(form_key)()
        return form, form.validate_on_submit()

    def _get_url(self, key):
        return self.config_or_default('URLS')[key]

    def _get_form(self, key):
        return self.config_or_default('FORMS')[key]

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

    def config_or_default(self, key):
        return (self._config[key] or self.get_defaults()[key])

    def _get_login_manager(self, app, anonymous_user):
        lm = LoginManager()
        lm.anonymous_user = anonymous_user or AnonymousUser
        #lm.localize_callback = localize_callback
        lm.login_view = self.config_or_default('BLUEPRINT_NAME')+'.login'
        lm.user_loader(self._datastore.get_user)
        lm.request_loader(_request_loader)

        if cv('FLASH_MESSAGES', app=app):
            lm.login_message, lm.login_message_category = cv('MSG_LOGIN', app=app)
            lm.needs_refresh_message, lm.needs_refresh_message_category = cv(
                'MSG_REFRESH', app=app)
        else:
            lm.login_message = None
            lm.needs_refresh_message = None

        lm.init_app(app)
        return lm

class UserMixin():
    pass
