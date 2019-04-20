from ..mixins import ValidatorMixin

class UserPassValidator(ValidatorMixin):

    def __init__(self, datastore, **kwargs):
        self._kwargs = kwargs

    def get_defaults(self):
        raise NotImplementedError()

    def routes(self, blueprint):
        raise NotImplementedError()
