from builtins import object
from flask_wtf import FlaskForm
from wtforms import ValidationError, validators

from .utils import _protect

#
#   Form Validators
#
class FormValidatorMixin(object):
    def __call__(self, form, field):
        if self.message and self.message.isupper():
            self.message = _protect.get_message(self.message)[0]
        return super(FormValidatorMixin, self).__call__(form, field)

class EqualTo(FormValidatorMixin, validators.EqualTo):
    pass
class Required(FormValidatorMixin, validators.DataRequired):
    pass
class Email(FormValidatorMixin, validators.Email):
    pass
class Length(FormValidatorMixin, validators.Length):
    pass


email_required = Required(message='EMAIL_NOT_PROVIDED')
email_validator = Email(message='INVALID_EMAIL_ADDRESS')
password_required = Required(message='PASSWORD_NOT_PROVIDED')
password_length = Length(min=6, max=128, message='PASSWORD_INVALID_LENGTH')

def unique_user_email(form, field):
    if _protect.validator._datastore.get_user(field.data) is not None:
        msg = get_message('EMAIL_ALREADY_ASSOCIATED', email=field.data)[0]
        raise ValidationError(msg)

def valid_user_email(form, field):
    form.user = _protect.validator._datastore.get_user(field.data)
    if form.user is None:
        raise ValidationError(get_message('USER_DOES_NOT_EXIST')[0])

#
#   Base Form
#
class BaseForm(FlaskForm):
    def __init__(self, method='POST', action='', encoding='multipart/form-data', *args, **kwargs):
        self.method = method
        self.action = action
        self.encoding = encoding
        if current_app.testing:
            self.TIME_LIMIT = None
        super().__init__(*args, **kwargs)

    def todict(self):
        fields = inspect.getmembers(form)
        return dict((key, value.data) for key, value in fields)
