from .mixins import SessionDatastoreMixin

class SessionCache(SessionDatastoreMixin):
    '''
        Will cache sessions in memory.
        New sessions will be created and stored
        by another SessionDatastore.
        Requires that the session class used
        extends IdentifiableSessionMixin
    '''
    def __init__(self, session_datastore):
        self.session_datastore=session_datastore
        self._cache = OrderedDict()

    def _normalize(self):
        print("Session cache size: %s" % len(self._cache))
        if len(self._cache) > self.num_to_store:
            while len(self._cache) > (self.num_to_store * 0.8):  # flush 20% of the cache
                self._cache.popitem(False)

    def new_session(self):
        session = self.parent.new_session()
        self._cache[session.get_id()] = session
        self._normalize()
        return session

    def remove(self, id):
        self.parent.remove(sid)
        if id in self._cache:
            del self._cache[id]

    def exists(self, id):
        if id in self._cache:
            return True
        return self.parent.exists(id)

    def get(self, id, digest):
        session = None
        if sid in self._cache:
            session = self._cache[sid]
            if session.hmac_digest != digest:
                session = None

            # reset order in OrderedDict
            del self._cache[sid]

        if not session:
            session = self.parent.get(sid, digest)

        self._cache[sid] = session
        self._normalize()
        return session

    def put(self, session):
        self.parent.put(session)
        if session.sid in self._cache:
            del self._cache[session.sid]
        self._cache[session.sid] = session
        self._normalize()
