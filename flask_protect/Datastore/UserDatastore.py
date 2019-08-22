class UserDatastoreMixin():
    def __init__(self, user_model):
        self.User_Model=user_model

    def get_user(self, id_or_email):
        raise NotImplementedError()

    def create_user(self, **kwargs):
        raise NotImplementedError()

    def find_user(self, *args, **kwargs):
        raise NotImplementedError()

    def toggle_active(self, user):
        user.active = not user.active
