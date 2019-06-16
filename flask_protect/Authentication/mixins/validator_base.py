class ValidatorMixin():
    def __init__(self, datastore, login_manager, **kwargs):
        self._kwargs = kwargs
        self._datastore=datastore
        self._login_manager=login_manager
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

    def initialize(self, app, blueprint, config, **kwargs):
        self._config = config

    def initialize_blueprint(self, app, blueprint, config, **kwargs):
        self.initialize(app, blueprint, config, **kwargs)
        self.routes(blueprint)

    def get_and_validate_form(self, form_key):
        form = self.get_form_config(form_key)()
        return form, form.validate_on_submit()

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
