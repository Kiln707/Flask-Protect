class ValidatorMixin():
    def __init__(self, **kwargs):
        self._kwargs = kwargs

    def get_defaults(self):
        raise NotImplementedError()

    def routes(self, blueprint):
        raise NotImplementedError()

class UserMixin():
    pass
