import unittest

def test_imports():
    from flask_protect.validator import FMail_Mixin, FormValidatorMixin, EqualTo, Required, Email, Length, email_required, \
        email_validator, password_required, password_length, unique_user_email, valid_user_email, BaseForm, SerializingValidatorMixin, \
        CryptContextValidatorMixin, ValidatorMixin

# Testing Flask Mail Validator
class FlaskMail_Validator_Mixin_TestCase(unittest.TestCase):
    from flask_protect import validator
    class FlaskMail_TestValidator(validator.FMail_Mixin):
        def send_mail_route(self):
            self.send_mail(recipients=['to@someone.com'], sender='from@someone.com', subject='Test text Message', template='test_msg.txt', plaintext=True, html=False, **{'msg': "this is a test"})
            self.send_mail(recipients=['to@someone.com'], sender='from@someone.com', subject='Test html Message', template='test_msg.html', plaintext=True, html=True, **{'msg': "this is a test"})
            return "True"

        def routes(self, blueprint):
            blueprint.add_url_rule(rule='/send_mail', endpoint='send_mail', view_func=self.send_mail_route)

    def setUp(self):
        try:
            from flask import Flask
            from flask_protect import Protect
            from flask_mail import Mail
        except ImportError:
            self.assertTrue(False)
        self.app = Flask(__name__)
        self.app.testing = True
        self.mail = Mail(self.app)
        validator = self.FlaskMail_TestValidator(datastore=None, login_manager=None)
        self.protect = Protect(app=self.app, validator=validator)
        self.ctx = self.app.test_request_context()
        self.ctx.push()

    def testDown(self):
        self.ctx.pop()

    def test_mail_send(self):
        with self.app.test_client() as client:
            with self.mail.record_messages() as outbox:
                response = client.get('/send_mail')
                assert response.status_code == 200
                assert response.data == b'True'
                msg = outbox[0]
                self.assertEqual(msg.recipients, ["to@someone.com"])
                self.assertEqual(msg.sender, "from@someone.com")
                self.assertEqual(msg.subject, "Test text Message")
                self.assertEqual(msg.body, "this is a test")
                msg = outbox[1]
                self.assertEqual(msg.recipients, ["to@someone.com"])
                self.assertEqual(msg.sender, "from@someone.com")
                self.assertEqual(msg.subject, "Test html Message")
                self.assertEqual(msg.body, "<html>\nthis is a test\n</html>")

# Testing It's Dangerous Serialization Validator.
class ItsDangerous_Serialization_Validator_Mixin_TestCase(unittest.TestCase):
    from flask_protect import validator
    class Serialization_TestValidator(validator.SerializingValidatorMixin):
        __DEFAULT_CONFIG={ 'SALT':{
            'TEST_SALT': 'salting'
            }}
        def routes(self, blueprint):
            pass

    def setUp(self):
        try:
            from flask import Flask
            from flask_protect import Protect
        except ImportError:
            self.assertTrue(False)
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'change-me'
        self.app.testing = True
        self.validator = self.Serialization_TestValidator(datastore=None, login_manager=None)
        self.protect = Protect(app=self.app, validator=self.validator)
        self.ctx = self.app.test_request_context()
        self.ctx.push()

    def testDown(self):
        self.ctx.pop()

    def test_get_serializer(self):
        self.assertIsNotNone(self.validator.get_serializer('TEST_SALT'))

    def test_remove_serializer(self):
        self.assertIsNotNone(self.validator.get_serializer('TEST_SALT'))
        self.validator.remove_serializer('TEST_SALT')
        self.assertIsNone(self.validator.get_serializer('TEST_SALT'))

    def test_generate_token(self):
        self.assertIsNotNone(self.validator.generate_token("TEST_SALT", 'test data'))

    def test_load_token(self):
        token = self.validator.generate_token("TEST_SALT", 'test data')
        expired, invalid, data = self.validator.load_token('TEST_SALT', token)
        self.assertFalse(expired)
        self.assertFalse(invalid)
        self.assertEqual(data, 'test data')

    def test_expired_token(self):
        from datetime import timedelta
        import time
        td = timedelta(seconds=3)
        token = self.validator.generate_token("TEST_SALT", 'test data')
        time.sleep(td.total_seconds())
        expired, invalid, data = self.validator.load_token('TEST_SALT', token, max_age=td)
        self.assertFalse(expired)
        self.assertFalse(invalid)
        self.assertEqual(data, 'test data')
        time.sleep(td.total_seconds())
        expired, invalid, data = self.validator.load_token('TEST_SALT', token, max_age='3 seconds')
        self.assertTrue(expired)
        self.assertFalse(invalid)
        self.assertEqual(data, 'test data')

    def test_invalid_token(self):
        token = self.validator.generate_token("TEST_SALT", 'test data')
        token = token[::-1]
        expired, invalid, data = self.validator.load_token('TEST_SALT', token)
        self.assertFalse(expired)
        self.assertTrue(invalid)
        self.assertNotEqual(data, 'test data')


# TODO: Test CryptContext
# TODO: Test Forms
