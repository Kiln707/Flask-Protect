def test_imports():
    from flask_protect import Protect, url_for_protect, is_safe_url, _protect

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
        return 'Hi'

    def test_redirect_route(self):
        from flask_protect.utils import get_redirect_url, set_session_next, get_session_next, get_request_next, get_request_form_next
        if get_request_next():
            assert get_redirect_url('/') == get_request_next()
            set_session_next('https://www.google.com')
            assert get_session_next(save=True) == 'https://www.google.com'
            assert get_redirect_url('/') != 'https://www.google.com'
            set_session_next('/redirect')
            assert get_session_next(save=True) == '/redirect'
            assert get_redirect_url('/') == '/redirect'
            assert get_redirect_url('/') == get_request_next()
        elif get_request_form_next():
            assert get_redirect_url('/') == get_request_form_next()
            set_session_next('https://www.google.com')
            assert get_session_next(save=True) == 'https://www.google.com'
            assert get_redirect_url('/') != 'https://www.google.com'
            set_session_next('/redirect')
            assert get_session_next(save=True) == '/redirect'
            assert get_redirect_url('/') == '/redirect'
            assert get_redirect_url('/') == get_request_form_next()
        else:
            assert get_redirect_url('/') == '/'
            set_session_next('https://www.google.com')
            assert get_session_next(save=True) == 'https://www.google.com'
            assert get_redirect_url('/') != 'https://www.google.com'
            set_session_next('/redirect')
            assert get_session_next(save=True) == '/redirect'
            assert get_redirect_url('/') == '/redirect'
            assert get_redirect_url('/') == '/'
            assert get_redirect_url('/', additional_urls=['www.google.com', '/redirect']) == '/redirect'
            assert get_redirect_url('www.facebook.com', additional_urls=['www.google.com',]) is None
        return 'True'

    def routes(self, blueprint):
        blueprint.add_url_rule(rule='/route', endpoint='route', view_func=self.route)
        blueprint.add_url_rule(rule='/redirect', endpoint='test_redirect_route', view_func=self.test_redirect_route)


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
    from flask_protect.utils import is_safe_url
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    def assert_safe(url, expected_safe, expected_code=None, allowed_hosts=[], require_https=False, allow_userpass=False, allowed_schemes=['http', 'https']):
        safe, error = is_safe_url(url, allowed_hosts=allowed_hosts, require_https=require_https, allow_userpass=allow_userpass, \
            allowed_schemes=allowed_schemes, pass_Exception=True)
        if error:
            assert error.code == expected_code
        assert safe == expected_safe

    with app.test_client() as client:
        with app.test_request_context():
            # Valid endpoint
            assert_safe('protect.route', True)
            # Relative URLs. Should pass as they are relative to local server
            assert_safe('images', True)    # Relative to current path
            assert_safe('/images', True)   # Relative to root (of website)
            # Not valid URL characters
            assert_safe('<>`^', False, expected_code=1)
            # starts with invalid unicode character
            assert_safe(u"\U000F0000", False, expected_code=5)
            #No Url
            assert_safe('       ', False, expected_code=0)
            assert_safe(None, False, expected_code=0)
            #
            #   Tests with hostname
            #
            # common URLs
            # Should fail due to not allowed hostname
            assert_safe('https://www.google.com', False, expected_code=9)
            assert_safe('https://google.com', False, expected_code=9)
            assert_safe('http://www.google.com', False, expected_code=9)
            assert_safe('http://google.com', False, expected_code=9)
            assert_safe('www.google.com', False, expected_code=9)
            assert_safe('google.com', False, expected_code=9)
            # Above urls with username and pass, allow_userpass set to default
            # Should fail due to username and pass not allowed in URL
            assert_safe('https://username:password@www.google.com', False, expected_code=8)
            assert_safe('https://username:password@google.com', False, expected_code=8)
            assert_safe('http://username:password@www.google.com', False, expected_code=8)
            assert_safe('http://username:password@google.com', False, expected_code=8)
            assert_safe('username:password@www.google.com', False, expected_code=4)
            assert_safe('username:password@google.com', False, expected_code=4)

            # Above urls with path of /test added
            # Should fail, but not due to path but above reasons
            assert_safe('https://www.google.com/test', False, expected_code=9)
            assert_safe('https://google.com/test', False, expected_code=9)
            assert_safe('http://www.google.com/test', False, expected_code=9)
            assert_safe('http://google.com/test', False, expected_code=9)
            assert_safe('www.google.com/test', False, expected_code=9)
            assert_safe('google.com/test', False, expected_code=9)
            assert_safe('https://username:password@www.google.com/test', False, expected_code=8)
            assert_safe('https://username:password@google.com/test', False, expected_code=8)
            assert_safe('http://username:password@www.google.com/test', False, expected_code=8)
            assert_safe('http://username:password@google.com/test', False, expected_code=8)
            assert_safe('username:password@www.google.com/test', False, expected_code=4)
            assert_safe('username:password@google.com/test', False, expected_code=4)
            #Above URLs with schemes with extra / in scheme/hostname
            # Should fail as does not generate proper net location
            assert_safe('https:///www.google.com', False, expected_code=4)
            assert_safe('https:///google.com', False, expected_code=4)
            assert_safe('http:///www.google.com', False, expected_code=4)
            assert_safe('http:///google.com', False, expected_code=4)
            assert_safe('https:///username:password@www.google.com', False, expected_code=4)
            assert_safe('https:///username:password@google.com', False, expected_code=4)
            assert_safe('http:///username:password@www.google.com', False, expected_code=4)
            assert_safe('http:///username:password@google.com', False, expected_code=4)
            assert_safe('https:///www.google.com/test', False, expected_code=4)
            assert_safe('https:///google.com/test', False, expected_code=4)
            assert_safe('http:///www.google.com/test', False, expected_code=4)
            assert_safe('http:///google.com/test', False, expected_code=4)
            assert_safe('https:///username:password@www.google.com/test', False, expected_code=4)
            assert_safe('https:///username:password@google.com/test', False, expected_code=4)
            assert_safe('http:///username:password@www.google.com/test', False, expected_code=4)
            assert_safe('http:///username:password@google.com/test', False, expected_code=4)
            # Unique urls above that start with ///
            # Should fail as /// is disallowed
            assert_safe('///www.google.com/test', False, expected_code=2)
            assert_safe('///google.com/test', False, expected_code=2)
            assert_safe('///www.google.com/test', False, expected_code=2)
            assert_safe('///google.com/test', False, expected_code=2)
            assert_safe('///username:password@www.google.com/test', False, expected_code=2)
            assert_safe('///username:password@google.com/test', False, expected_code=2)
            assert_safe('///username:password@www.google.com/test', False, expected_code=2)
            assert_safe('///username:password@google.com/test', False, expected_code=2)
            # unallowed Scheme
            assert_safe('ftps://www.google.com', False, expected_code=7)
            assert_safe('ftps://google.com', False, expected_code=7)
            assert_safe('ftp://www.google.com', False, expected_code=7)
            assert_safe('ftp://google.com', False, expected_code=7)
            assert_safe('ftps://username:password@www.google.com', False, expected_code=7)
            assert_safe('ftps://username:password@google.com', False, expected_code=7)
            assert_safe('ftp://username:password@www.google.com', False, expected_code=7)
            assert_safe('ftp://username:password@google.com', False, expected_code=7)
            assert_safe('ftps://www.google.com/test', False, expected_code=7)
            assert_safe('ftps://google.com/test', False, expected_code=7)
            assert_safe('ftp://www.google.com/test', False, expected_code=7)
            assert_safe('ftp://google.com/test', False, expected_code=7)
            assert_safe('ftps://username:password@www.google.com/test', False, expected_code=7)
            assert_safe('ftps://username:password@google.com/test', False, expected_code=7)
            assert_safe('ftp://username:password@www.google.com/test', False, expected_code=7)
            assert_safe('ftp://username:password@google.com/test', False, expected_code=7)
            # Starts with //
            # Should not fail due to scheme
            assert_safe('//www.google.com', False, expected_code=9)
            assert_safe('//google.com', False, expected_code=9)
            assert_safe('//www.google.com', False, expected_code=9)
            assert_safe('//google.com', False, expected_code=9)
            assert_safe('//username:password@www.google.com', False, expected_code=8)
            assert_safe('//username:password@google.com', False, expected_code=8)
            assert_safe('//username:password@www.google.com', False, expected_code=8)
            assert_safe('//username:password@google.com', False, expected_code=8)
            assert_safe('//www.google.com/test', False, expected_code=9)
            assert_safe('//google.com/test', False, expected_code=9)
            assert_safe('//www.google.com/test', False, expected_code=9)
            assert_safe('//google.com/test', False, expected_code=9)
            assert_safe('//username:password@www.google.com/test', False, expected_code=8)
            assert_safe('//username:password@google.com/test', False, expected_code=8)
            # Requires HTTPS:
            # Should Fail due to not HTTPS
            assert_safe('http://www.google.com', False, expected_code=6, require_https=True)
            assert_safe('http://google.com', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@www.google.com', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@google.com', False, expected_code=6, require_https=True)
            assert_safe('http://www.google.com/test', False, expected_code=6, require_https=True)
            assert_safe('http://google.com/test', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@www.google.com/test', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@google.com/test', False, expected_code=6, require_https=True)
            # Should Not Fail due to HTTPS
            assert_safe('https://www.google.com', False, expected_code=9, require_https=True)
            assert_safe('https://google.com', False, expected_code=9, require_https=True)
            assert_safe('https://username:password@www.google.com', False, expected_code=8, require_https=True)
            assert_safe('https://username:password@google.com', False, expected_code=8, require_https=True)
            assert_safe('https://www.google.com/test', False, expected_code=9, require_https=True)
            assert_safe('https://google.com/test', False, expected_code=9, require_https=True)
            assert_safe('https://username:password@www.google.com/test', False, expected_code=8, require_https=True)
            assert_safe('https://username:password@google.com/test', False, expected_code=8, require_https=True)
            # Allow UserPass, Should not fail due to username, password
            assert_safe('https://username:password@www.google.com', False, allow_userpass=True, expected_code=9)
            assert_safe('https://username:password@google.com', False, allow_userpass=True, expected_code=9)
            assert_safe('http://username:password@www.google.com', False, allow_userpass=True, expected_code=9)
            assert_safe('http://username:password@google.com', False, allow_userpass=True, expected_code=9)
            assert_safe('username:password@www.google.com', False, allow_userpass=True, expected_code=4)
            assert_safe('username:password@google.com', False, allow_userpass=True, expected_code=4)
            # Allow FTP, FTPS schemes, should not fail due to scheme
            assert_safe('ftps://www.google.com', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://google.com', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://www.google.com', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://google.com', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://username:password@www.google.com', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftps://username:password@google.com', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@www.google.com', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@google.com', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftps://www.google.com/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://google.com/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://www.google.com/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://google.com/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://username:password@www.google.com/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftps://username:password@google.com/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@www.google.com/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@google.com/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            # Allow certain outside urls, UserPass should Fail, FTP should Fail
            assert_safe('https://www.google.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://google.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://www.google.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://google.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('www.google.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('google.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://www.facebook.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://facebook.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://www.facebook.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://facebook.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('www.facebook.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('facebook.com', True, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://username:password@www.google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=8)
            assert_safe('https://username:password@google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=8)
            assert_safe('http://username:password@www.google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=8)
            assert_safe('http://username:password@google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=8)
            assert_safe('username:password@www.google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=4)
            assert_safe('username:password@google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=4)
            assert_safe('ftps://www.google.com', False, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://google.com', False, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://www.google.com', False, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://google.com', False, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@www.google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@www.google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@google.com', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://www.google.com/test', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://google.com/test', False, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://www.google.com/test', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://google.com/test', False, allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@www.google.com/test', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@google.com/test', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@www.google.com/test', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@google.com/test', False, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            # Allow certain outside urls AND Userpass NOT FTP
            assert_safe('https://www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://username:password@www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://username:password@google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://username:password@www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://username:password@google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'])
            assert_safe('username:password@www.google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=4)
            assert_safe('username:password@google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=4)
            assert_safe('ftps://www.google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://www.google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@www.google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@www.google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://www.google.com/test', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://google.com/test', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://www.google.com/test', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://google.com/test', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@www.google.com/test', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@google.com/test', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@www.google.com/test', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@google.com/test', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], expected_code=7)
            # Allow certain outside urls AND Userpass NOT FTP
            assert_safe('https://www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://username:password@www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://username:password@google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://username:password@www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://username:password@google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('username:password@www.google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'], \
                expected_code=4)
            assert_safe('username:password@google.com', False, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'], \
                expected_code=4)
            assert_safe('ftps://www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@www.google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@google.com', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://www.google.com/test', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://google.com/test', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://www.google.com/test', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://google.com/test', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@www.google.com/test', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@google.com/test', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@www.google.com/test', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@google.com/test', True, allow_userpass=True, \
                allowed_hosts=['www.google.com', 'google.com', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            #
            #   Tests with IPv4
            #   192.168.0.233
            # common URLs
            # Should fail due to not allowed hostname
            assert_safe('https://www.192.168.0.233', False, expected_code=9)
            assert_safe('https://192.168.0.233', False, expected_code=9)
            assert_safe('http://www.192.168.0.233', False, expected_code=9)
            assert_safe('http://192.168.0.233', False, expected_code=9)
            assert_safe('www.192.168.0.233', False, expected_code=9)
            assert_safe('192.168.0.233', False, expected_code=9)
            # Above urls with username and pass, allow_userpass set to default
            # Should fail due to username and pass not allowed in URL
            assert_safe('https://username:password@www.192.168.0.233', False, expected_code=8)
            assert_safe('https://username:password@192.168.0.233', False, expected_code=8)
            assert_safe('http://username:password@www.192.168.0.233', False, expected_code=8)
            assert_safe('http://username:password@192.168.0.233', False, expected_code=8)
            assert_safe('username:password@www.192.168.0.233', False, expected_code=4)
            assert_safe('username:password@192.168.0.233', False, expected_code=4)
            # Above urls with path of /test added
            # Should fail, but not due to path but above reasons
            assert_safe('https://www.192.168.0.233/test', False, expected_code=9)
            assert_safe('https://192.168.0.233/test', False, expected_code=9)
            assert_safe('http://www.192.168.0.233/test', False, expected_code=9)
            assert_safe('http://192.168.0.233/test', False, expected_code=9)
            assert_safe('www.192.168.0.233/test', False, expected_code=9)
            assert_safe('192.168.0.233/test', False, expected_code=9)
            assert_safe('https://username:password@www.192.168.0.233/test', False, expected_code=8)
            assert_safe('https://username:password@192.168.0.233/test', False, expected_code=8)
            assert_safe('http://username:password@www.192.168.0.233/test', False, expected_code=8)
            assert_safe('http://username:password@192.168.0.233/test', False, expected_code=8)
            assert_safe('username:password@www.192.168.0.233/test', False, expected_code=4)
            assert_safe('username:password@192.168.0.233/test', False, expected_code=4)
            # unallowed Scheme
            assert_safe('ftps://www.192.168.0.233', False, expected_code=7)
            assert_safe('ftps://192.168.0.233', False, expected_code=7)
            assert_safe('ftp://www.192.168.0.233', False, expected_code=7)
            assert_safe('ftp://192.168.0.233', False, expected_code=7)
            assert_safe('ftps://username:password@www.192.168.0.233', False, expected_code=7)
            assert_safe('ftps://username:password@192.168.0.233', False, expected_code=7)
            assert_safe('ftp://username:password@www.192.168.0.233', False, expected_code=7)
            assert_safe('ftp://username:password@192.168.0.233', False, expected_code=7)
            assert_safe('ftps://www.192.168.0.233/test', False, expected_code=7)
            assert_safe('ftps://192.168.0.233/test', False, expected_code=7)
            assert_safe('ftp://www.192.168.0.233/test', False, expected_code=7)
            assert_safe('ftp://192.168.0.233/test', False, expected_code=7)
            assert_safe('ftps://username:password@www.192.168.0.233/test', False, expected_code=7)
            assert_safe('ftps://username:password@192.168.0.233/test', False, expected_code=7)
            assert_safe('ftp://username:password@www.192.168.0.233/test', False, expected_code=7)
            assert_safe('ftp://username:password@192.168.0.233/test', False, expected_code=7)
            # Requires HTTPS:
            # Should Fail due to not HTTPS
            assert_safe('http://www.192.168.0.233', False, expected_code=6, require_https=True)
            assert_safe('http://192.168.0.233', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@www.192.168.0.233', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@192.168.0.233', False, expected_code=6, require_https=True)
            assert_safe('http://www.192.168.0.233/test', False, expected_code=6, require_https=True)
            assert_safe('http://192.168.0.233/test', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@www.192.168.0.233/test', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@192.168.0.233/test', False, expected_code=6, require_https=True)
            # Should Not Fail due to HTTPS
            assert_safe('https://www.192.168.0.233', False, expected_code=9, require_https=True)
            assert_safe('https://192.168.0.233', False, expected_code=9, require_https=True)
            assert_safe('https://username:password@www.192.168.0.233', False, expected_code=8, require_https=True)
            assert_safe('https://username:password@192.168.0.233', False, expected_code=8, require_https=True)
            assert_safe('https://www.192.168.0.233/test', False, expected_code=9, require_https=True)
            assert_safe('https://192.168.0.233/test', False, expected_code=9, require_https=True)
            assert_safe('https://username:password@www.192.168.0.233/test', False, expected_code=8, require_https=True)
            assert_safe('https://username:password@192.168.0.233/test', False, expected_code=8, require_https=True)
            # Allow UserPass, Should not fail due to username, password
            assert_safe('https://username:password@www.192.168.0.233', False, allow_userpass=True, expected_code=9)
            assert_safe('https://username:password@192.168.0.233', False, allow_userpass=True, expected_code=9)
            assert_safe('http://username:password@www.192.168.0.233', False, allow_userpass=True, expected_code=9)
            assert_safe('http://username:password@192.168.0.233', False, allow_userpass=True, expected_code=9)
            assert_safe('username:password@www.192.168.0.233', False, allow_userpass=True, expected_code=4)
            assert_safe('username:password@192.168.0.233', False, allow_userpass=True, expected_code=4)
            # Allow FTP, FTPS schemes, should not fail due to scheme
            assert_safe('ftps://www.192.168.0.233', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://192.168.0.233', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://www.192.168.0.233', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://192.168.0.233', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://username:password@www.192.168.0.233', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftps://username:password@192.168.0.233', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@www.192.168.0.233', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@192.168.0.233', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftps://www.192.168.0.233/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://192.168.0.233/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://www.192.168.0.233/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://192.168.0.233/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://username:password@www.192.168.0.233/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftps://username:password@192.168.0.233/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@www.192.168.0.233/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@192.168.0.233/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            # Allow certain outside urls, UserPass should Fail, FTP should Fail
            assert_safe('https://www.192.168.0.233', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://192.168.0.233', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://www.192.168.0.233', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://192.168.0.233', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('www.192.168.0.233', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('192.168.0.233', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://www.facebook.com', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://facebook.com', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://www.facebook.com', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://facebook.com', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('www.facebook.com', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('facebook.com', True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://username:password@www.192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=8)
            assert_safe('https://username:password@192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=8)
            assert_safe('http://username:password@www.192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=8)
            assert_safe('http://username:password@192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=8)
            assert_safe('username:password@www.192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=4)
            assert_safe('username:password@192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=4)
            assert_safe('ftps://www.192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://www.192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@www.192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@www.192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@192.168.0.233', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://www.192.168.0.233/test', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://192.168.0.233/test', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://www.192.168.0.233/test', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://192.168.0.233/test', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@www.192.168.0.233/test', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@192.168.0.233/test', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@www.192.168.0.233/test', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@192.168.0.233/test', False, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            # Allow certain outside urls AND Userpass NOT FTP
            assert_safe('https://www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('facebook.com', True, allow_userpass=True, allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://username:password@www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('https://username:password@192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://username:password@www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('http://username:password@192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'])
            assert_safe('username:password@www.192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=4)
            assert_safe('username:password@192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=4)
            assert_safe('ftps://www.192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://www.192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@www.192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@www.192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://www.192.168.0.233/test', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://192.168.0.233/test', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://www.192.168.0.233/test', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://192.168.0.233/test', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@www.192.168.0.233/test', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftps://username:password@192.168.0.233/test', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@www.192.168.0.233/test', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            assert_safe('ftp://username:password@192.168.0.233/test', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], expected_code=7)
            # Allow certain outside urls AND Userpass NOT FTP
            assert_safe('https://www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('www.facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('facebook.com', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://username:password@www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://username:password@192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://username:password@www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://username:password@192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('username:password@www.192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'], \
                expected_code=4)
            assert_safe('username:password@192.168.0.233', False, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'], \
                expected_code=4)
            assert_safe('ftps://www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@www.192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@192.168.0.233', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://www.192.168.0.233/test', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://192.168.0.233/test', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://www.192.168.0.233/test', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://192.168.0.233/test', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@www.192.168.0.233/test', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@192.168.0.233/test', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@www.192.168.0.233/test', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@192.168.0.233/test', True, allow_userpass=True, \
                allowed_hosts=['www.192.168.0.233', '192.168.0.233', 'www.facebook.com', 'facebook.com'], allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            # test local ip
            assert_safe('https://www.127.0.0.1/test', False, expected_code=9) # Fail as subdomain not allowed
            assert_safe('https://127.0.0.1/test', True)
            # test malformed ip
            assert_safe('https://www.127.0.0.1.2/test', False, expected_code=9)
            assert_safe('https://127.0.0.1.2/test', False, expected_code=9)
            assert_safe('https://www.192.168.0.233', False, allowed_hosts=['www.192.168.0.3.233', '192.168.0.3.233'], expected_code=9)
            assert_safe('https://192.168.0.233', False, allowed_hosts=['www.192.168.0.3.233', '192.168.0.3.233'], expected_code=9)
            assert_safe('http://www.192.168.0.233', False, allowed_hosts=['www.192.168.0.3.233', '192.168.0.3.233'], expected_code=9)
            assert_safe('http://192.168.0.233', False, allowed_hosts=['www.192.168.0.3.233', '192.168.0.3.233'], expected_code=9)
            #
            #   Tests with IPv6
            #   2001:0db8:85a3:0000:0000:8a2e:0370:7334
            # common URLs
            # Should fail due to not allowed hostname
            assert_safe('https://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=9)
            assert_safe('https://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=9)
            assert_safe('http://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=9)
            assert_safe('http://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=9)
            assert_safe('www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=4)
            assert_safe('2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=4)
            # Above urls with username and pass, allow_userpass set to default
            # Should fail due to username and pass not allowed in URL
            assert_safe('https://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=8)
            assert_safe('https://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=8)
            assert_safe('http://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=8)
            assert_safe('http://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=8)
            assert_safe('username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=4)
            assert_safe('username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=4)
            # Above urls with path of /test added
            # Should fail, but not due to path but above reasons
            assert_safe('https://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=9)
            assert_safe('https://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=9)
            assert_safe('http://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=9)
            assert_safe('http://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=9)
            assert_safe('www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=4)
            assert_safe('2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=4)
            assert_safe('https://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=8)
            assert_safe('https://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=8)
            assert_safe('http://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=8)
            assert_safe('http://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=8)
            assert_safe('username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=4)
            assert_safe('username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=4)
            # unallowed Scheme
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=7)
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=7)
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=7)
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=7)
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=7)
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=7)
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=7)
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=7)
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=7)
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=7)
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=7)
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=7)
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=7)
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=7)
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=7)
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=7)
            # Requires HTTPS:
            # Should Fail due to not HTTPS
            assert_safe('http://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=6, require_https=True)
            assert_safe('http://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=6, require_https=True)
            assert_safe('http://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=6, require_https=True)
            assert_safe('http://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=6, require_https=True)
            assert_safe('http://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=6, require_https=True)
            # Should Not Fail due to HTTPS
            assert_safe('https://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=9, require_https=True)
            assert_safe('https://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=9, require_https=True)
            assert_safe('https://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=8, require_https=True)
            assert_safe('https://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, expected_code=8, require_https=True)
            assert_safe('https://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=9, require_https=True)
            assert_safe('https://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=9, require_https=True)
            assert_safe('https://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=8, require_https=True)
            assert_safe('https://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, expected_code=8, require_https=True)
            # Allow UserPass, Should not fail due to username, password
            assert_safe('https://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, expected_code=9)
            assert_safe('https://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, expected_code=9)
            assert_safe('http://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, expected_code=9)
            assert_safe('http://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, expected_code=9)
            assert_safe('username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, expected_code=4)
            assert_safe('username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, expected_code=4)
            # Allow FTP, FTPS schemes, should not fail due to scheme
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=8)
            # Allow certain outside urls, UserPass should Fail, FTP should Fail
            assert_safe('https://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('https://2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('http://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('http://2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=4)
            assert_safe('2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=4)
            assert_safe('https://www.facebook.com', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('https://facebook.com', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('http://www.facebook.com', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('http://facebook.com', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('www.facebook.com', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('facebook.com', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('https://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=8)
            assert_safe('https://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=8)
            assert_safe('http://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=8)
            assert_safe('http://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=8)
            assert_safe('username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=4)
            assert_safe('username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=4)
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            # Allow certain outside urls AND Userpass NOT FTP
            assert_safe('https://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('https://2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('http://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('http://2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=4)
            assert_safe('2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=4)
            assert_safe('https://www.facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('https://facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('http://www.facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('http://facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('www.facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=9)
            assert_safe('https://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('https://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('http://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('http://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'])
            assert_safe('username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=4)
            assert_safe('username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=4)
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], expected_code=7)
            # Allow certain outside urls AND Userpass NOT FTP
            assert_safe('https://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=4)
            assert_safe('2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=4)
            assert_safe('https://www.facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('https://facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('http://www.facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('http://facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('www.facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('facebook.com', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=9)
            assert_safe('https://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('https://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('http://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=4)
            assert_safe('username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', False, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'], expected_code=4)
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftps://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@www.2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            assert_safe('ftp://username:password@2001:0db8:85a3:0000:0000:8a2e:0370:7334/test', True, allow_userpass=True, \
                allowed_hosts=['www.2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], \
                allowed_schemes=['http', 'https', 'ftp', 'ftps'])
            # Test Local IP and different ipv6 formats
            assert_safe('https://www.::1', False, expected_code=9)
            assert_safe('https://::1', True)
            assert_safe('http://www.0000:0000:0000:0000:0000:0000:0000:0001', False, expected_code=9)
            assert_safe('http://www.0000:0000:0000:0000:0000:0000:0000:0001', True, allowed_hosts=['www.::1',])
            assert_safe('http://0000:0000:0000:0000:0000:0000:0000:0001', True)
            assert_safe('https://www.2001::7334', True, \
                allowed_hosts=['www.2001:0000:0000:0000:0000:0000:0000:7334', '2001:0000:0000:0000:0000:0000:0000:7334'])
            assert_safe('https://2001::7334', True, allowed_hosts=['www.2001:0000:0000:0000:0000:0000:0000:7334', '2001:0000:0000:0000:0000:0000:0000:7334'])
            assert_safe('http://www.2001::7334', True, \
                allowed_hosts=['www.2001:0000:0000:0000:0000:0000:0000:7334', '2001:0000:0000:0000:0000:0000:0000:7334'])
            assert_safe('http://2001::7334', True, allowed_hosts=['www.2001:0000:0000:0000:0000:0000:0000:7334', '2001:0000:0000:0000:0000:0000:0000:7334'])
            assert_safe('https://www.2001::7335', False, allowed_hosts=['www.2001::7334', '2001::7334'], expected_code=9)
            assert_safe('https://2001::73345', False, allowed_hosts=['www.2001::7334', '2001::7334'], expected_code=9)
            assert_safe('http://www.2001::7335', False, allowed_hosts=['www.2001::7334', '2001::7334'], expected_code=9)
            assert_safe('http://2001::7335', False, allowed_hosts=['www.2001::7334', '2001::7334'], expected_code=9)

            assert_safe('http://www.eu.2001::7334', False, allowed_hosts=['www.us.2001::7334', '2001::7334'], expected_code=9)
            #Malformed ipv6
            assert_safe('http://www.20V1::7334', False, allowed_hosts=['www.20V1::7334', '20V1::7334'], expected_code=9)
            assert_safe('http://20V1::7334', False, allowed_hosts=['www.20V1::7334', '20V1::7334'], expected_code=9)
            assert_safe('http://www.2001::7334', False, allowed_hosts=['www.20V1::7334', '20V1::7334'], expected_code=9)
            assert_safe('http://2001::7334', False, allowed_hosts=['www.20V1::7334', '20V1::7334'], expected_code=9)

def test_session_next():
    from flask import Flask
    from flask_protect import Protect
    from flask_protect.utils import set_session_next, get_session_next, get_url
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    with app.test_client() as client:
        with app.test_request_context():
            assert get_session_next() == None
            set_session_next(get_url('protect.route'))
            assert get_session_next() == '/route'
            assert get_session_next() == None

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

def test_get_redirect_no_request():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    with app.test_client() as client:
        with app.app_context() as ctx:
            ctx.push()
            response = client.get('/redirect')
            assert response.status_code == 200
            assert response.data == b'True'
            ctx.pop()

def test_get_redirect_request_next():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    request = {'next': '/redirect'}
    with app.test_client() as client:
        with app.app_context() as ctx:
            ctx.push()
            response = client.get('/redirect', query_string=request)
            assert response.status_code == 200
            assert response.data == b'True'
            ctx.pop()

def test_get_redirect_request_form_next():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    request = {'next': '/redirect'}
    with app.test_client() as client:
        with app.app_context() as ctx:
            ctx.push()
            response = client.get('/redirect', content_type='multipart/form-data', data=request)
            assert response.status_code == 200
            assert response.data == b'True'
            ctx.pop()

def test_get_redirect_no_request():
    from flask import Flask
    from flask_protect import Protect
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'

    datastore = UserDatastoreMixin(User_Model)
    validator = TestValidator(datastore)
    protect = Protect(app=app, validator=validator)

    with app.test_client() as client:
        with app.app_context() as ctx:
            ctx.push()
            response = client.get('/redirect')
            assert response.status_code == 200
            assert response.data == b'True'
            ctx.pop()
