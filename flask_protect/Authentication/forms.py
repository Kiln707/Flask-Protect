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

class LoginForm(BaseForm):
    identifier=StringField('identifier', validators=[])
    password=PasswordField('password',validators=[])
    remember=BooleanField('remember_me')
    submit=SubmitField('login')

class RegisterIdentifierForm(BaseForm):
    identifier=StringField('identifier', validators=[])
    email_address=StringField('email', validators=[])
    confirm_email=StringField('confirm_email', validators=[])
    password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('register')

class RegisterEmailForm(BaseForm):
    email_address=StringField('email', validators=[])
    confirm_email=StringField('confirm_email', validators=[])
    password=PasswordField('password',validators=[])
    confirm_password=PasswordField('confirm_password',validators=[])
    submit=SubmitField('register')
