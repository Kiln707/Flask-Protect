
class AuthenticationDatastoreMixin():
    def __init__(self, user_model):
        self.UserModel=user_model

    def get_user_by_id(self, id):
        raise NotImplementedError()

    def get_user(self, identifier):
        if type(identifier) is int:
            user = self.get_user_by_id(identifier)
        else:
            user = self.get_user_by_email(identifier)
        return user

    def create_user(self, **kwargs):
        raise NotImplementedError()

class UserPassDatastoreMixin():
    def get_user_by_email(self, email):
        raise NotImplementedError()

    def get_user_by_identifier(self, identifier):
        raise NotImplementedError()

    def identifier_exists(self, identifier):
        raise NotImplementedError()

    def email_address_exists(self, address):
        raise NotImplementedError()

    def get_user(self, identifier):
        user = super().get_user(identifier)
        if not user:
            user = self.get_user_by_identifier(identifier)
        return user
