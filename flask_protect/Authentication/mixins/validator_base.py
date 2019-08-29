from collections import ChainMap
from flask import request

class ValidatorMixin():
    def __init__(self, datastore, login_manager, **kwargs):
        self._kwargs = kwargs
        self._datastore=datastore
        self._login_manager=login_manager
        self._config=None

    ############################################################################################
    #   Requires override
    ############################################################################################
    #
    # User Functions
    #
    def get_user(self, identifier):
        raise NotImplementedError()

    def create_user(self, **kwargs):
        raise NotImplementedError()

    def change_user_password(self, identifier, current_password, new_password):
        raise NotImplementedError()

    def reset_user_password(self, identifier, new_password):
        raise NotImplementedError()

    def login_user(self, user=None):
        raise NotImplementedError()

    def logout_user(self):
        raise NotImplementedError()
    #
    # validator actions
    #
    def routes(self, blueprint):
        raise NotImplementedError()

    def initialize(self, app, blueprint, **kwargs):
        pass

    ###########################################################################################
    #   Does not require override
    ###########################################################################################
    #
    # User Functions
    #
    def login_user(self, user, remember=False, duration=None, force=False, fresh=True):
        self._login_manager.login_user(user=user, remember=remember, duration=duration, force=force, fresh=fresh)

    def logout_user(self):
        self._login_manager.logout_user()

    def current_user(self):
        user = self._login_manager.current_user()
        return self._datastore.get_user_by_id(user.id)

    def get_field(form, key):
        if hasattr(form, self.get_form_field_config(key)):
            return getattr(form, self.get_form_field_config(key))
        elif hasattr(form, key):
            return getattr(form, key)
        return None

    #
    # validator actions
    #
    def initialize_blueprint(self, app, blueprint, **kwargs):
        self.initialize(app, blueprint, **kwargs)
        self.routes(blueprint)

    def initialize_config(self, config):
        self._config = config

    def get_and_validate_form(self, form_key, **kwargs):
        form = self.get_form_config(form_key)(**kwargs)
        if request.method == 'POST':
            return form, form.validate_on_submit()
        return form, False

    def get_defaults(self):
        defaults = {}
        if type(self) is not ValidatorMixin:
            defaults = super().get_defaults().copy()
        return dict(ChainMap(self.__DEFAULT_CONFIG, defaults))

    def get_url_config(self, key):
        return self.config_or_default('URLS')[key]

    def get_action_config(self, key):
        return self.config_or_default('ACTIONS')[key]

    def get_form_config(self, key):
        return self.config_or_default('FORMS')[key]

    def get_form_field_config(self, key):
        return self.config_or_default('FORM_FIELDS')[key]

    def get_msg_config(self, key):
        return self.config_or_default('MSGS')[key]

    def get_template_config(self, key):
        return self.config_or_default('TEMPLATES')[key]

    def get_redirect_config(self, key):
        return self.config_or_default('REDIRECT')[key]

    def get_user_field(self, key):
        return self.config_or_default('USER_FIELDS')[key]

    def config_or_default(self, key):
        return (self._config[key] or self.get_defaults()[key])
