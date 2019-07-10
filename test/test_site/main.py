from flask import Flask, render_template
from sqlalchemy import create_engine

def create_test_database():
    try:
        conn = sqlite3.connect(':memory:')
    except Error as e:
        print(e)
    finally:
        conn.close()

def create_app():
    from flask_protect.Datastore.mixins import UserPassDatastoreMixin
    class TestDatastore(UserPassDatastoreMixin):
        class User():
            def __init__(self, id, username, email_address, password):
                self.id=id
                self.username=username
                self.email_address=email_address
                self.password=password
                self.is_active=True
                self.is_authenticated=True
                self.is_anonymous=False
            def get_id(self):
                return self.id
        def __init__(self):
            self.users = []
            self.UserModel = TestDatastore.User
        def create_user(self, username, email_address, password):
            user = self.UserModel(id=len(self.users), username=username, email_address=email_address, password=password)
            self.users.append(user)
            return user
        def get_user_by_email(self, email):
            for user in self.users:
                if email == user.email_address:
                    return user
            return None
        def get_user_by_identifier(self, identifier):
            for user in self.users:
                if identifier == user.username:
                    return user
            return None
        def get_user_by_id(self, id):
            for user in self.users:
                if id == user.id:
                    return user
            return None

    app = Flask(__name__)
    app.config['SECRET_KEY']='meh'
    #All other setup
    from flask_protect import Protect
    from flask_protect.Authentication import UserPassValidator
    from flask_protect.Session import FLogin_Manager
    datastore = TestDatastore()
    login_manager = FLogin_Manager(user_loader=datastore.get_user_by_id, app=app, user=TestDatastore.User)
    login_manager.user_loader(datastore.get_user_by_id)
    validator = UserPassValidator(datastore, login_manager=login_manager, crypt_context=None, **{'LAYOUT_TEMPLATE':'hub.html', 'REDIRECT':{'LOGIN': '/',
    'LOGOUT': '/',
    'REGISTER': '/',
    'FORGOT_PASS': '/',
    'RESET_PASS': '/',
    'CHANGE_PASS': '/',
    'CONFIRM_EMAIL': '/'}})
    Protect(app=app, validator=validator,  register_blueprint=True)
    if not datastore.get_user_by_id(0):
        admin = datastore.create_user('admin','admin@admin.com', validator.hash_password('admin'))
    return app

def blueprint_endpoints():
    from flask_protect.utils import _protect
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
        from flask_protect.utils import _validator
        print(_validator.validate_user('admin', 'admin'))
        return render_template('hub.html')

    app.run()
