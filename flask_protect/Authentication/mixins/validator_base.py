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
    def get_defaults(self):
        raise NotImplementedError()

    def routes(self, blueprint):
        raise NotImplementedError()

    ###########################################################################################
    #   Does not require override
    ###########################################################################################
    #
    # User Functions
    #
    def get_user(self, identifier):
        if isinstance(identifier, self._datastore.UserModel):
            return identifier
        user=None
        if isinstance(identifier, int):
            user = self._datastore.get_user_by_id(identifier)
        if ( self.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') and not user ) or self.config_or_default('USE_EMAIL_AS_ID'):
            user = self._datastore.get_user_by_email(identifier)
        #If allowing both email and username and user not already found by email, OR not using email
        if ( self.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') and not user ) or not self.config_or_default('USE_EMAIL_AS_ID'):
            user = self._datastore.get_user_by_identifier(identifier)
        return user

    def login_user(self, user, remember=False, duration=None, force=False, fresh=True):
        self._login_manager.login_user(user=user, remember=remember, duration=duration, force=force, fresh=fresh)

    def logout_user(self):
        self._login_manager.logout_user()

    def current_user(self):
        user = self._login_manager.current_user()
        return self._datastore.get_user_by_id(user.id)

    #
    # validator actions
    #
    def initialize(self, app, blueprint, config, **kwargs):
        self._config = config

    def initialize_blueprint(self, app, blueprint, config, **kwargs):
        self.initialize(app, blueprint, config, **kwargs)
        self.routes(blueprint)

    def get_and_validate_form(self, form_key, **kwargs):
        form = self.get_form_config(form_key)(**kwargs)
        if request.method == 'POST':
            return form, form.validate_on_submit()
        return form, False

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
