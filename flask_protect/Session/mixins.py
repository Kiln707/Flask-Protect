class UserSessionMixin():
    def is_authenticated(self):
        raise NotImplementedError()

    def is_active(self):
        raise NotImplementedError()

    def is_anonymous(self):
        return False

    def get_id(self):
        return None

class AnonymousUserSessionMixin(UserSessionMixin):
    def is_authenticated(self):
        return False

    def is_active(self):
        return False

    def is_anonymous(self):
        return True


class LoginManagerMixin():

    #
    #   Utility methods
    #
    def unauthorized(self):
        raise NotImplementedError()

    def needs_refresh(self):
        raise NotImplementedError()

    def is_login_fresh(self):
        raise NotImplementedError()

    def current_user(self):
        raise NotImplementedError()

    def login_user(self, user, remember=False, duration=None, force=False, fresh=True):
        raise NotImplementedError()

    def logout_user(self):
        raise NotImplementedError()

    def confirm_login(self):
        raise NotImplementedError()

    #
    #   Decorator Functions
    #
    def login_required(self, func):
        raise NotImplementedError()

    def fresh_login_required(self, func):
        raise NotImplementedError()
