

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
from flask_protect.Datastore import UserDatastoreMixin
class UserDatastoreMixin():
    def __init__(self, user_model):
        self.UserModel = user_model
        self.users = []

    def get_user(self, id):
        if isinstance(id, self.UserModel):
            return id
        elif 0 <= id < len(self.users):
            return self.users[id]
        return None

    def create_user(self, **kwargs):
        id = len(self.users)
        newUser = self.UserModel(id=id, **kwargs)
        self.users.append(newUser)
        return newUser

    def set_user_password(self, id, newPassword):
        user = self.get_user(id)
        user.password = newPassword


from flask_protect.Authentication import ValidatorMixin
class TestValidator(ValidatorMixin):
    def __init__(self, datastore, login_manager, **kwargs):
        super().__init__(datastore, login_manager, **kwargs)

    def create_user(self, **kwargs):
        return self._datastore.create_user(**kwargs)

    def change_user_password(self, identifier, current_password, new_password):
        user = self._datastore.get_user(identifier)
        if user.password == current_password:
            self.reset_user_password(user)

    def reset_user_password(self, identifier, new_password):
        self._datastore.set_user_password(identifier)

    def login_user(self, user=None):
        raise NotImplementedError()

    def logout_user(self):
        raise NotImplementedError()

    def routes(self, blueprint):
        raise NotImplementedError()

    def initialize(self, app, blueprint, **kwargs):
        pass


def test_initialize_validator():
    pass
