from ..mixins import ValidatorMixin

class UserPassValidator(ValidatorMixin):
    __DEFAULT_CONFIG={
        'AUTO_UPDATE_HASH':True
    }

    def __init__(self, datastore, **kwargs):
        self._datastore=datastore
        self._kwargs = kwargs

    def validate(self, identifier, password):
        user = self._datastore.get_user(identifier)
        if user:
            if self.config['AUTO_UPDATE_HASH']:
                


    def _validate(self, password, hash):


    def _validate_and_update(self, password, hash):
        pass

    def get_defaults(self):
        raise NotImplementedError()

    def routes(self, blueprint):
        raise NotImplementedError()
