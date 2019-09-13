def test_imports():
    from flask_protect import Protect, url_for_protect, safe_url, _protect

#
#   Without Flask
#
def test_Setup_with_no_flaskapp():
    from flask_protect import Protect
    protect = Protect()

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
#   With FlaskApp
#
def test_Setup_with_flaskapp():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'
    from flask_protect import Protect
    protect = Protect(app=app)

def test_configuration():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'
    from flask_protect import Protect
    defaults={
        #Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect(app=app)
    for key, value in defaults.items():
        assert protect._config[key] == value

def test_custom_configuration():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'
    from flask_protect import Protect
    new_config={
        #Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect(app=app, **new_config)
    for key, value in new_config.items():
        assert protect._config[key] == value

def test_custom_configuration_missing_values():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'
    from flask_protect import Protect
    new_config={
        #Basic Functionality
        'BLUEPRINT_NAME': None,
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect(app=app, **new_config)
    for key, value in new_config.items():
        if key == 'BLUEPRINT_NAME':
            assert protect.get_config(key) != value
        else:
            assert protect.get_config(key) == value

def test_get_config():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    from flask_protect import Protect
    defaults={
        #Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect(app=app)
    for key, value in defaults.items():
        assert protect.get_config(key) == value

def test_get_config_with_incomplete_config():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    from flask_protect import Protect
    defaults={
        #Basic Functionality
        'BLUEPRINT_NAME': 'protect',
        'URL_PREFIX':None,
        'SUBDOMAIN':None,
        'FLASH_MESSAGES': True,
    }
    protect = Protect(app=app)
    protect._config.pop('BLUEPRINT_NAME')
    assert 'BLUEPRINT_NAME' not in protect._config
    for key, value in defaults.items():
        assert protect.get_config(key) == value

#
#   Testing basic Validator setup and use
#
class User_Model():
    def __init__(self, id, identifier, password):
        self.id=id
        self.identifier = identifier
        self.password=password

from flask_protect.Datastore import UserDatastoreMixin
class UserDatastoreMixin():
    def __init__(self, user_model):
        self.UserModel = user_model
        self.users = []

    def get_user(self, **kwargs):
        if 'id' in kwargs:
            return self.users[kwargs['id']]
        elif 'identifier' in kwargs:
            for user in self.users:
                if user.identifier == kwargs['identifier']:
                    return user
        elif 'user' in kwargs:
            return kwargs['user']
        return None

    def create_user(self, **kwargs):
        id = len(self.users)
        newUser = self.UserModel(id=id, **kwargs)
        self.users.append(newUser)
        return newUser

    def set_user_password(self, id, newPassword):
        user = self.get_user(user = id)
        user.password = newPassword


from flask_protect.Authentication import ValidatorMixin
from flask import session
class TestValidator(ValidatorMixin):

    __DEFAULT_CONFIG = {
        'TEST': 'TEST'
    }

    def __init__(self, datastore, login_manager=None, **kwargs):
        super().__init__(datastore, login_manager, **kwargs)

    def validate_user(self, user, password):
        if user and user.password == password:
            return True
        return False

    def change_user_password(self, identifier, current_password, new_password):
        user = self._datastore.get_user(identifier)
        if user.password == current_password:
            self.reset_user_password(user)

    def reset_user_password(self, identifier, new_password):
        self._datastore.set_user_password(identifier, new_password)

    def login_user(self, user=None):
        session['user_id'] = user.id

    def logout_user(self):
        del session['user_id']

    def user_logged_in(self):
        return 'user_id' in session

    def get_defaults(self):
        return self.__DEFAULT_CONFIG.copy()

    def route(self):
        assert True

    def test_redirect_route(self):
        from flask_protect.utils import get_redirect_url
        return get_redirect_url('/')

    def routes(self, blueprint):
        blueprint.add_url_rule(rule='/route', endpoint='route', view_func=self.route)
        blueprint.add_url_rule(rule='/redirect', endpoint='test_redirect_route', view_func=self.route)


def test_initialize_validator():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

#
#   Config Tests
#

def test_validator_configuration():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'
    from flask_protect import Protect
    defaults={
        'TEST': 'TEST'
    }
    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)
    for key, value in defaults.items():
        assert protect.validator._config[key] == value

def test_validator_custom_configuration():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'
    from flask_protect import Protect
    new_config={
        'TEST': 'NEWTEST'
    }
    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore, **new_config)
    protect = Protect(app=app, validator=validator)
    for key, value in new_config.items():
        assert protect.validator._config[key] == value

def test_validator_custom_configuration_missing_values():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'
    from flask_protect import Protect
    new_config={
        'TEST': 'NEWTEST'
    }
    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore, **new_config)
    protect = Protect(app=app, validator=validator)
    protect.validator._config.pop('TEST')
    for key, value in new_config.items():
        assert protect.validator.get_config(key) != value

def test_validator_config():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'
    from flask_protect import Protect
    defaults={
        'TEST': 'TEST'
    }
    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)
    for key, value in defaults.items():
        assert protect.validator.get_config(key) == value

def test_validator_config_with_incomplete_config():
    from flask import Flask
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    from flask_protect import Protect
    defaults={
        'TEST': 'TEST'
    }
    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)
    protect.validator._config.pop('TEST')
    assert 'TEST' not in protect.validator._config
    for key, value in defaults.items():
        assert protect.validator.get_config(key) == value

#
#   Functions
#

def test_validator_create_user():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    assert len(datastore.users) == 0
    protect.validator.create_user(identifier='test_user', password='password')
    assert len(datastore.users) == 1

def test_validator_get_user():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)
    user = protect.validator.create_user(identifier='test_user', password='password')
    test_user = protect.validator.get_user(id=user.id)
    assert test_user == user
    assert test_user.id == user.id
    assert test_user.identifier == user.identifier
    assert test_user.password == user.password

def test_validator_validate_user_correct_pass():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)
    user = protect.validator.create_user(identifier='test_user', password='password')
    assert protect.validator.validate_user(user, 'password')

def test_validator_validate_user_incorrect_pass():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)
    user = protect.validator.create_user(identifier='test_user', password='password')
    assert not protect.validator.validate_user(user, 'bad_password')

def test_validator_login_and_logout_user():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)
    protect.validator.create_user(identifier='test_user', password='password')

    with app.test_client() as client:
        with app.test_request_context():
            user = protect.validator.get_user(identifier='test_user')
            assert protect.validator.validate_user(user, 'password')
            protect.validator.login_user(user)
            assert 'user_id' in session and session['user_id'] == user.id
            assert protect.validator.user_logged_in()
            protect.validator.logout_user()
            assert 'user_id' not in session

def test_validator_change_user_password():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)
    protect.validator.create_user(identifier='test_user', password='password')

    with app.test_client() as client:
        with app.test_request_context():
            user = protect.validator.get_user(identifier='test_user')
            assert user.password == 'password'
            protect.validator.change_user_password(user, 'password', 'new_password')
            assert user.password == 'new_password'

def test_validator_change_user_password():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)
    protect.validator.create_user(identifier='test_user', password='password')

    with app.test_client() as client:
        with app.test_request_context():
            user = protect.validator.get_user(identifier='test_user')
            assert user.password == 'password'
            protect.validator.reset_user_password(user, 'new_password')
            assert user.password == 'new_password'

#
#   Protect Utility tests
#
def test_protect_url_for():
    from flask import Flask
    from flask_protect import Protect, url_for_protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    with app.test_client() as client:
        with app.test_request_context():
            assert protect.url_for('route') == '/route'
            assert url_for_protect('route') == '/route'

def test_get_url():
    from flask import Flask
    from flask_protect import Protect
    from flask_protect.utils import get_url
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    with app.test_client() as client:
        with app.test_request_context():
            assert get_url('protect.route') == '/route'
            assert get_url('https://www.google.com') == 'https://www.google.com'

def test_safe_url():
    from flask import Flask
    from flask_protect import Protect
    from flask_protect.utils import safe_url
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    with app.test_client() as client:
        with app.test_request_context():
            assert safe_url('protect.route')
            assert not safe_url('https://www.google.com')
            assert not safe_url('       ')
            assert not safe_url(None)

def test_cookie_next():
    from flask import Flask
    from flask_protect import Protect
    from flask_protect.utils import set_cookie_next, get_cookie_next, clear_cookie_next, get_url
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    with app.test_client() as client:
        with app.test_request_context():
            assert get_cookie_next() == None
            set_cookie_next(get_url('protect.route'))
            assert get_cookie_next() == '/route'
            clear_cookie_next()
            assert get_cookie_next() == None

def test_request_withno_next():
    from flask import Flask
    from flask_protect import Protect
    from flask_protect.utils import get_request_next, get_url
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    with app.test_client() as client:
        with app.test_request_context():
            assert get_request_next() == None

def test_client():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    with app.test_client() as client:
        with app.test_request_context():
            from flask_protect.utils import set_cookie_next
            print(client.get('/redirect'))
            assert client.get('/redirect') == '/'
