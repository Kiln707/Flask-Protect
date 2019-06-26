from flask import (_request_ctx_stack, current_app, request, session, url_for, has_request_context)
from flask.signals import Namespace
from flask_login import LoginManager, login_required, current_user
from flask_login import login_user as _login_user
from flask_login import logout_user as _logout_user
from flask_login.signals import (user_loaded_from_cookie, user_loaded_from_header, user_loaded_from_request, user_unauthorized, user_needs_refresh, user_accessed, session_protected)

class FLogin_Manager():
    def __init__(self, user_loader=None, request_loader=None, login_view=None, app=None, user=None, anonymous_user=None):
        super().__init__()
        self.User = user
        self.anonymous_user=anonymous_user
        self._login_manager=LoginManager(app=app)
        #   LoginManager Signals
        _signals = Namespace()
        self.user_logged_in = _signals.signal('logged-in')
        self.user_logged_out = _signals.signal('logged-out')
        self.user_login_confirmed = _signals.signal('login-confirmed')
        self.user_loaded_from_cookie = user_loaded_from_cookie
        self.user_loaded_from_header = user_loaded_from_header
        self.user_loaded_from_request = user_loaded_from_request
        self.user_unauthorized = user_unauthorized
        self.user_needs_refresh = user_needs_refresh
        self.user_acessed = user_accessed
        self.session_protection = session_protected
        self.EXEMPT_METHODS=[]

    #
    #   Utility methods
    #
    def unauthorized(self):
        return self._login_manager.unauthorized()

    def needs_refresh(self):
        self.user_needs_refresh.send()
        return self._login_manager.needs_refresh()

    def is_login_fresh(self):
        return session.get('_fresh', False)

    def get_user(self):
        if has_request_context() and not hasattr(_request_ctx_stack.top, 'user'):
            self._login_manager._load_user()
        return getattr(_request_ctx_stack.top, 'user', None)

    def login_user(self, user, remember=False, duration=None, force=False, fresh=True):
        return _login_user(user)

    def logout_user(self):
        return _logout_user()

    def confirm_login(self):
        '''
        This sets the current session as fresh. Sessions become stale when they
        are reloaded from a cookie.
        '''
        session['_fresh'] = True
        session['_id'] = self._login_manager._session_identifier_generator()
        self.user_login_confirmed.send(current_app._get_current_object())
        #Signal confirm login

    #
    #   Decorator Functions
    #
    def login_required(self, func):
        '''
        If you decorate a view with this, it will ensure that the current user is
        logged in and authenticated before calling the actual view. (If they are
        not, it calls the :attr:`LoginManager.unauthorized` callback.) For
        example::
            @app.route('/post')
            @login_required
            def post():
                pass
        If there are only certain times you need to require that your user is
        logged in, you can do so with::
            if not current_user.is_authenticated:
                return current_app.login_manager.unauthorized()
        ...which is essentially the code that this function adds to your views.
        It can be convenient to globally turn off authentication when unit testing.
        To enable this, if the application configuration variable `LOGIN_DISABLED`
        is set to `True`, this decorator will be ignored.
        .. Note ::
            Per `W3 guidelines for CORS preflight requests
            <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_,
            HTTP ``OPTIONS`` requests are exempt from login checks.
        :param func: The view function to decorate.
        :type func: function
        '''
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if request.method in EXEMPT_METHODS:
                return func(*args, **kwargs)
            elif current_app.config.get('LOGIN_DISABLED'):
                return func(*args, **kwargs)
            elif not self.get_user().is_authenticated:
                return self._login_manager.unauthorized()
            return func(*args, **kwargs)
        return decorated_view

    def fresh_login_required(self, func):
        '''
        If you decorate a view with this, it will ensure that the current user's
        login is fresh - i.e. their session was not restored from a 'remember me'
        cookie. Sensitive operations, like changing a password or e-mail, should
        be protected with this, to impede the efforts of cookie thieves.
        If the user is not authenticated, :meth:`LoginManager.unauthorized` is
        called as normal. If they are authenticated, but their session is not
        fresh, it will call :meth:`LoginManager.needs_refresh` instead. (In that
        case, you will need to provide a :attr:`LoginManager.refresh_view`.)
        Behaves identically to the :func:`login_required` decorator with respect
        to configutation variables.
        .. Note ::
            Per `W3 guidelines for CORS preflight requests
            <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_,
            HTTP ``OPTIONS`` requests are exempt from login checks.
        :param func: The view function to decorate.
        :type func: function
        '''
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if request.method in EXEMPT_METHODS:
                return func(*args, **kwargs)
            elif current_app.config.get('LOGIN_DISABLED'):
                return func(*args, **kwargs)
            elif not self.get_user().is_authenticated:
                return self._login_manager.unauthorized()
            elif not login_fresh():
                return self._login_manager.needs_refresh()
            return func(*args, **kwargs)
        return decorated_view

    #
    #   Callback settings
    #
    def user_loader(self, callback):
        return self._login_manager.user_loader(callback)

    def request_loader(self, callback):
        return self._login_manager.request_loader(callback)

    def unauthorized_handler(self, callback):
        return self._login_manager.unauthorized_handler(callback)

    def needs_refresh_handler(self, callback):
        return self._login_manager.needs_refresh_handler(callback)

    def user_is_anonymous_user(self):
        return not current_user.is_authenticated

    def user_is_authenticated(self, silent=False):
        if request.method in self.EXEMPT_METHODS:
            return True
        elif current_app.config.get('LOGIN_DISABLED'):
            return True
        elif not current_user.is_authenticated:
            if silent:
                return False
            return self.unauthorized()
        return True

    #
    #   Decorators
    #
    def anonymous_user_reqired(self, f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if self.user_is_anonymous_user():
                return redirect(self._post_login_redirect)
            return f(*args, **kwargs)
        return wrapper

    def login_required(self, f):
        return login_required(f)

    #
    #
    #
    def initialize(self, login_redirect, post_login_redirect):
        self._login_redirect=login_redirect
        self._post_login_redirect=post_login_redirect
