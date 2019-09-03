class UserDatastoreMixin():
    def __init__(self, user_model):
        self.UserModel=user_model

    def get_user(self, id):
        raise NotImplementedError()

    def create_user(self, **kwargs):
        raise NotImplementedError()

    def remove_user(self, id):
        raise NotImplementedError()

    def find_user(self, *args, **kwargs):
        raise NotImplementedError()

    def set_user_password(self, id, newPassword):
        raise NotImplementedError()

    def toggle_active(self, user):
        user.active = not user.active
