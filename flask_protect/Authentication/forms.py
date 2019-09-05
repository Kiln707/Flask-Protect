import inspect
from flask import Markup, current_app, flash, request
from flask_wtf import FlaskForm
from wtforms import BooleanField, Field, HiddenField, PasswordField, \
StringField, SubmitField, ValidationError, validators

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
    username=StringField('username', validators=[])
    email_address=StringField('email', validators=[])
    confirm_email=StringField('confirm_email', validators=[])
    password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('Register')

    def to_dict(self, form):
        fields={}
        for member in form:
            if isinstance(member, Field):
                fields[member.name] = member
        return dict((key, value.data) for key, value in fields.items())

class RegisterEmailForm(BaseForm):
    email_address=StringField('email', validators=[])
    confirm_email=StringField('confirm_email', validators=[])
    password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('Register')

    def to_dict(self, form):
        fields={}
        for member in form:
            if isinstance(member, Field):
                fields[member.name] = member
        return dict((key, value.data) for key, value in fields)

class ForgotPasswordForm(BaseForm):
    email_address=StringField('email', validators=[])
    submit=SubmitField('Send Instructions')

class ResetPasswordForm(BaseForm):
    user_id=HiddenField("user")
    password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('Reset Password')

class ChangePasswordForm(BaseForm):
    current_password=PasswordField('current password',validators=[])
    password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('Change Password')

class ConfirmEmailForm(BaseForm):
    code=StringField('confirmation code', validators=[])
    submit=SubmitField('Submit')
