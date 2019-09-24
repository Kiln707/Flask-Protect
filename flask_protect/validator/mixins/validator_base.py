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
    def validate_user(self, user, password):
        raise NotImplementedError()

    def change_user_password(self, identifier, current_password, new_password):
        raise NotImplementedError()

    #
    # validator actions
    #
    def routes(self, blueprint):
        raise NotImplementedError()

    def initialize(self, app, blueprint, **kwargs):
        pass

    def post_initialization(self):
        pass

    ###########################################################################################
    #   Does not require override
    ###########################################################################################
    #
    # User Functions
    #
    def create_user(self, **kwargs):
        return self._datastore.create_user(**kwargs)

    def get_user(self, **kwargs):
        return self._datastore.get_user(**kwargs)

    def set_user_password(self, identifier, new_password):
        self._datastore.set_user_password(identifier, new_password)

    def login_user(self, user, remember=False, duration=None, force=False, fresh=True):
        self._login_manager.login_user(user=user, remember=remember, duration=duration, force=force, fresh=fresh)

    def logout_user(self):
        self._login_manager.logout_user()

    def login_user(self, user=None):
        self._login_manager.login_user(user)

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
        for key, value in self._kwargs.items():
            self._config[key] = value

    def get_and_validate_form(self, form_key, **kwargs):
        form = self.get_form_config(form_key)(**kwargs)
        if request.method == 'POST':
            return form, form.validate_on_submit()
        return form, False

    def get_defaults(self):
        if hasattr(self, '__DEFAULT_CONFIG'):
            return self.__DEFAULT_CONFIG.copy()
        return dict()

    def get_config(self, key):
        return self._config.get(key, self.get_defaults()[key])
