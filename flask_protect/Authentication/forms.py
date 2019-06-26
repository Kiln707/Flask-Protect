import inspect
from flask import Markup, current_app, flash, request
from flask_wtf import FlaskForm
from wtforms import BooleanField, Field, HiddenField, PasswordField, \
StringField, SubmitField, ValidationError, validators
from .utils import _datastore

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

class LoginForm(BaseForm):
    identifier=StringField('identifier', validators=[])
    password=PasswordField('password',validators=[])
    remember=BooleanField('remember_me')
    submit=SubmitField('Login')

class RegisterIdentifierForm(BaseForm):
    identifier=StringField('identifier', validators=[])
    email_address=StringField('email', validators=[])
    confirm_email=StringField('confirm_email', validators=[])
    password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('Register')

    def todict(self):
        def is_field_and_user_attr(member):
            return isinstance(member, Field) and \
                hasattr(_datastore.UserModel, member.label)
        fields = inspect.getmembers(self, is_field_and_user_attr)
        return dict((key, value.data) for key, value in fields)

class RegisterEmailForm(BaseForm):
    email_address=StringField('email', validators=[])
    confirm_email=StringField('confirm_email', validators=[])
    password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('Register')

    def todict(self):
        def is_field_and_user_attr(member):
            return isinstance(member, Field) and \
                hasattr(_datastore.user_model, member.name)
        fields = inspect.getmembers(form, is_field_and_user_attr)
        return dict((key, value.data) for key, value in fields)

class ForgotPasswordForm(BaseForm):
    email_address=StringField('email', validators=[])
    submit=SubmitField('Send Instructions')

class ResetPasswordForm(BaseForm):
    new_password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('Reset PASSWORD')

class ChangePasswordForm(BaseForm):
    current_password=PasswordField('current password',validators=[])
    password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('Change Password')

class ConfirmEmailForm(BaseForm):
    code=StringField('confirmation code', validators=[])
    submit=SubmitField('Submit')
