class ValidatorMixin():
    def __init__(self, **kwargs):
        self._kwargs = kwargs
        self._config=None

    def get_defaults(self):
        raise NotImplementedError()

    def routes(self, blueprint):
        raise NotImplementedError()

    def initialize(self, config):
        self._config = kwargs['config']

    def initialize_blueprint(self, blueprint, config, **kwargs):
        self.initialize(config)
        self.routes(blueprint)

class UserMixin():
    pass
