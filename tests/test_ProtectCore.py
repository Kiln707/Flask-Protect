

def test_imports():
    from flask_protect import Protect, url_for_protect, safe_url, _protect, _validator
    from flask_protect.utils import get_within_delta

def test_Setup_with_no_flaskapp():
    from flask_protect import Protect
    protect = Protect()

#
#   Without Flask
#

#
#   Configuration Tests
#

def test_configuration_with_no_flaskapp():
    from flask_protect import Protect
    defaults={
        #Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect()
    for key, value in defaults.items():
        assert protect._config[key] == value

def test_custom_configuration_with_no_flaskapp():
    from flask_protect import Protect
    new_config={
        #Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect(**new_config)
    for key, value in new_config.items():
        assert protect._config[key] == value

def test_custom_configuration_missing_values_with_no_flaskapp():
    from flask_protect import Protect
    new_config={
        #Basic Functionality
        'BLUEPRINT_NAME': None,
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect(**new_config)
    for key, value in new_config.items():
        if key == 'BLUEPRINT_NAME':
            assert protect.get_config(key) != value
        else:
            assert protect.get_config(key) == value

def test_get_config_with_no_flaskapp():
    from flask_protect import Protect
    defaults={
        #Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect()
    for key, value in defaults.items():
        assert protect.get_config(key) == value

def test_get_config_with_incomplete_config_with_no_flaskapp():
    from flask_protect import Protect
    defaults={
        #Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect()
    protect._config.pop('BLUEPRINT_NAME')
    assert 'BLUEPRINT_NAME' not in protect._config
    for key, value in defaults.items():
        assert protect.get_config(key) == value

#
#   Testing Validator setup
#
from flask_protect.Authentication import ValidatorMixin
class TestValidator(ValidatorMixin):
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

    def initialize(self, app, blueprint, **kwargs):
        pass

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
        if not user and ( ( self.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') and not user ) or self.config_or_default('USE_EMAIL_AS_ID') ):
            user = self._datastore.get_user_by_email(identifier)
        #If allowing both email and username and user not already found by email, OR not using email
        if not user and ( ( self.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') and not user ) or not self.config_or_default('USE_EMAIL_AS_ID') ):
            user = self._datastore.get_user_by_identifier(identifier)
        return user

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


def test_initialize_validator():
    pass
