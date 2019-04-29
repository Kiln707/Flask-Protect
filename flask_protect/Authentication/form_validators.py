from builtins import object
from .utils import _datastore

#
# Copied from Flask Security
#

class FormValidatorMixin(object):
    def __call__(self, form, field):
        if self.message and self.message.isupper():
            self.message = _protect.get_message(self.message)[0]
        return super(FormValidatorMixin, self).__call__(form, field)

class EqualTo(ValidatorMixin, validators.EqualTo):
    pass
class Required(ValidatorMixin, validators.DataRequired):
    pass
class Email(ValidatorMixin, validators.Email):
    pass
class Length(ValidatorMixin, validators.Length):
    pass


email_required = Required(message='EMAIL_NOT_PROVIDED')
email_validator = Email(message='INVALID_EMAIL_ADDRESS')
password_required = Required(message='PASSWORD_NOT_PROVIDED')
password_length = Length(min=6, max=128, message='PASSWORD_INVALID_LENGTH')

def unique_user_email(form, field):
    if _datastore.get_user(field.data) is not None:
        msg = get_message('EMAIL_ALREADY_ASSOCIATED', email=field.data)[0]
        raise ValidationError(msg)

def valid_user_email(form, field):
    form.user = _datastore.get_user(field.data)
    if form.user is None:
raise ValidationError(get_message('USER_DOES_NOT_EXIST')[0])
