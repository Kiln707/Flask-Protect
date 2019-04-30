from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY']='meh'
    #All other setup
    from flask_protect import Protect
    from flask_protect.Authentication import UserPassValidator
    validator = UserPassValidator(None, crypt_context=None)
    Protect(app=app, validator=validator, register_blueprint=True)
    return app



if __name__ == '__main__':
    import sys, os
    package=os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    sys.path.insert(0,package)
    app = create_app()
    app.run()
