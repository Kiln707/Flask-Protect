class DatastoreMixin():
    def __init__(self, db):
        self.db=db

    def commit(self):
        pass

    def put(self, model):
        raise NotImplementedError()

    def delete(self, model):
        raise NotImplementedError()
