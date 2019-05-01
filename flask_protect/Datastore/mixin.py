
class DatastoreMixin():
    pass

class UserPassDatastoreMixin():

    def get_user_by_email(self, email):
        pass

    def get_user_by_identifier(self, identifier):
        pass

    def get_user(self, identifier):
        pass
