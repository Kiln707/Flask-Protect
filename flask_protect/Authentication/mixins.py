class ValidatorMixin():
    def __init__(self, **kwargs):
        self._kwargs = kwargs

    def get_defaults(self):
        raise NotImplementedError()

    def routes(self, blueprint):
        raise NotImplementedError()

    def initialize_blueprint(self, blueprint, **kwargs):
        self.routes(blueprint)

class UserMixin():
    pass
