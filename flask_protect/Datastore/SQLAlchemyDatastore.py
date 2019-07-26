from .mixin.datastore import datastore

class SQLAlchemyDatastore(Datastore):
    def commit(self):
        self.db.session.commit()

    def put(self, model):
        self.db.session.add(model)

    def delete(self, model):
        self.db.session.delete(model)
