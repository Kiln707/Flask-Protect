import inspect
from flask import Markup, current_app, flash, request
from flask_login import current_user
from flask_wtf import FlaskForm
from speaklater import make_lazy_gettext
from wtforms import BooleanField, Field, HiddenField, PasswordField, \
StringField, SubmitField, ValidationError, validators

class BaseForm(FlaskForm):
    def __init__(self, *args, **kwargs):
        if current_app.testing:
            self.TIME_LIMIT = None
        super(Form, self).__init__(*args, **kwargs)

class LoginForm(BaseForm):
    identifier=StringField('identifier', validators=[])
    password=PasswordField('password',validators=[])
    remember=BooleanField('remember_me')
    submit=SubmitField('login')
