from builtins import object
from ..utils import _protect

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


#
#
#
