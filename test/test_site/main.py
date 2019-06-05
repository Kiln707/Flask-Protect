from flask import Flask, render_template

def create_app():
    from flask_protect.Datastore.mixins import UserPassDatastoreMixin
    class TestDatastore(UserPassDatastoreMixin):
        class User():
            def __init__(self):
                self.id=1
                self.username='test'
                self.email_address='test@test.com'
                self.password=None
        def __init__(self):
            self.user = TestDatastore.User()
            self.UserModel = TestDatastore.User
        def get_user_by_email(self, email):
            if email == self.user.email_address:
                return self.user
            return None
        def get_user_by_identifier(self, identifier):
            if identifier == self.user.username:
                return self.user
            return None
        def get_user_by_id(self, id):
            if id == self.user.id:
                return self.user
            return None

    app = Flask(__name__)
    app.config['SECRET_KEY']='meh'
    #All other setup
    from flask_protect import Protect
    from flask_protect.Authentication import UserPassValidator
    from flask_protect.Session import FLogin_Manager
    datastore = TestDatastore()
    login_manager = FLogin_Manager(user_loader=datastore.get_user_by_id, app=app, user=TestDatastore.User)
    validator = UserPassValidator(datastore, login_manager=login_manager, crypt_context=None, **{'LAYOUT_TEMPLATE':'hub.html'})
    Protect(app=app, validator=validator,  register_blueprint=True)
    datastore.user.password = validator.hash_password('test')
    return app

def blueprint_endpoints():
    from flask_protect.utils import _protect
    for rule in app.url_map.iter_rules():
        print(type(rule.rule))
    rules = [rule.endpoint for rule in app.url_map.iter_rules() if rule.endpoint.split('.')[0]==_protect.blueprint.name and '<' not in rule.rule]
    return rules

def _ctx():
    return dict(endpoints=blueprint_endpoints)

if __name__ == '__main__':
    import sys, os
    package=os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    sys.path.insert(0,package)
    app = create_app()
    app.context_processor(_ctx)

    @app.route('/')
    def root():
        return render_template('hub.html')

    app.run()
