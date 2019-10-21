import unittest

def test_imports():
    from flask_protect.validator import FMail_Mixin, FormValidatorMixin, EqualTo, Required, Email, Length, email_required, \
        email_validator, password_required, password_length, unique_user_email, valid_user_email, BaseForm, SerializingValidatorMixin, \
        CryptContextValidatorMixin, ValidatorMixin

class FlaskMail_Validator_Mixin_TestCase(unittest.TestCase):
    from flask_protect import Protect, validator
    class FlaskMail_TestValidator(validator.Fmail_Mixin):
        def send_mail_route(self):
            self.send_mail()

        def routes(self, blueprint):
            blueprint.add_url_rule(rule='/send_mail', endpoint='send_mail', view_func=self.send_mail_route)

    def setUp(self):
        try:
            from flask_mail import Mail
        except ImportError:
            self.assertTrue(False)
        self.app = Flask(__name__)
        self.app.testing = True
        self.mail = Mail(self.app)
        self.ctx = self.app.test_request_context()
        self.ctx.push()
        self.outbox = self.mail.record_messages()

    def testDown(self):
        self.ctx.pop()


def test_FlaskMail_Validate_mixin():
    pass

def test_Form_mixins():
    pass

def test_ItsDangerous_Serialization_mixin():
    pass

def test_PassLib_CryptContext_mixin():
    pass
