from builtins import object
from flask.sessions import SessionMixin

class SessionDatastoreMixin(object):
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
