import unittest

def test_imports():
    from flask_protect.validator import FMail_Mixin, FormValidatorMixin, EqualTo, Required, Email, Length, email_required, \
        email_validator, password_required, password_length, unique_user_email, valid_user_email, BaseForm, SerializingValidatorMixin, \
        CryptContextValidatorMixin, ValidatorMixin

class FlaskMail_Validator_Mixin_TestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)



def test_FlaskMail_Validate_mixin():
    pass

def test_Form_mixins():
    pass

def test_ItsDangerous_Serialization_mixin():
    pass

def test_PassLib_CryptContext_mixin():
    pass
