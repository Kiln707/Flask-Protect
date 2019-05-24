from builtins import object
from flask.sessions import SessionMixin, SessionInterface
from uuid import uuid4
from werkzeug.datastructures import CallbackDict

class IdentifiableSessionMixin(SessionMixin):
    def get_id(self):
        'get a unique identifier for this session'
        raise NotImplementedError

#Datastore is not always needed, used as middleman
class SessionDatastoreMixin(object):
    ''' Datastore Mixin for creating a new Session DataManagement '''
    def create(self):
        'Create a new session'
        raise NotImplementedError

    def exists(self, sid):
        'Does the given session-id exist?'
        raise NotImplementedError

    def remove(self, sid):
        'Remove the session'
        raise NotImplementedError

    def get(self, sid, digest):
        'Retrieve a managed session by session-id, checking the HMAC digest'
        raise NotImplementedError

    def put(self, session):
        'Store a managed session'
        raise NotImplementedError
