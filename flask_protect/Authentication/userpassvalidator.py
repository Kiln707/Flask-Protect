from flask import render_template, redirect, current_app
from werkzeug import LocalProxy
from .mixins import SerializingValidatorMixin, CryptContextValidatorMixin, FMail_Mixin
from .forms import LoginForm, RegisterIdentifierForm, RegisterEmailForm, ForgotPasswordForm, ResetPasswordForm, ChangePasswordForm, ConfirmEmailForm
from .utils import _protect, _validator
from ..utils import safe_url, set_request_next, url_for_protect, get_redirect_url, get_request_form
from ..Session import FLogin_Manager
import os

#
#   UserPass Specific methods
#
def login(form):
    user=None
    #   GET User
    #If allowing both email and username, or using email
    user = _validator.get_user_from_form(form)
    #       VALIDATE User
    if _validator.validate_user(user, _validator.get_field(form, 'PASSWORD').data):
        _validator.login_user(user) #Valid, login user
        return True
    #Invalid username/email/identifier or password. Add error to field
    if _validator.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL'):
        _validator.get_field(form, 'IDENTIFIER').errors.append(_validator.get_msg_config('BAD_USER_PASS')[0])
    elif _validator.config_or_default('USE_EMAIL_AS_ID'):
        _validator.get_field(form, 'EMAIL').errors.append(_validator.get_msg_config('BAD_EMAIL_PASS')[0])
    else:
        _validator.get_field(form, 'IDENTIFIER').errors.append(_validator.get_msg_config('BAD_USER_PASS')[0])
    return False

def register(form):
    user_data = form.to_dict(form)
    user=_validator.create_user(**user_data)
    #if confirm email address
    #generate code, and email to address
    return True

def forgot_password(form):
    # Verify account exists with given email address/Get User
    user = _validator.get_user_from_form(form=form)
    # generate code to allow reset password
    if user:
        if not _validator.config_or_default('FORGOT_PASS_DIRECT_TO_RESET_PASS') and _validator.config_or_default('SEND_EMAIL'):
            # Send email, with link/code to reset password, redirect
            _validator.send_reset_password_instructions(user)
        return True
    return False

def reset_password(form):
    #   take new password, hash and update user DB with new password
    user = _validator.get_user_from_form(form=form)
    if user:
        _validator.reset_user_password(user, _validator.get_field(form=form, key='PASSWORD').data)
        return True
    return False

def change_password(form):
    #   Check that current password is correct for user
    #   take new password, hash and update user DB with new password
    user = _validator.current_user()
    if user:
        current_password = _validator.get_field(form=form, key='CURRENT_PASSWORD').data
        new_password = _validator.get_field(form=form, key='PASSWORD').data
        return _validator.change_user_password(identifier=user, current_password=current_password, new_password=new_password)
    return False

#
#
#
class UserPassValidator(SerializingValidatorMixin, CryptContextValidatorMixin, FMail_Mixin):
    __DEFAULT_CONFIG={
        'ALLOW_BOTH_IDENTIFIER_AND_EMAIL':True, #Can a identifier or email address be used for validating?
        'USE_EMAIL_AS_ID':True, #Should email be used if not both
        'AUTO_UPDATE_HASH':True,
        'LAYOUT_TEMPLATE':'protect/base.html',
        'FORGOT_PASS_DIRECT_TO_RESET_PASS':False,
        'SEND_EMAIL':True,
        'EMAIL_SENDER': LocalProxy(lambda: current_app.config.get('MAIL_DEFAULT_SENDER', 'no-reply@localhost')),
        'EMAIL_PLAINTEXT': True,
        'EMAIL_HTML': True,
        'EMAIL_SUBJECT':{
            'REGISTER': 'Welcome',
            'CONFIRM_INSTRUCTIONS': 'Please confirm your email',
            'PASSWORD_RESET_NOTICE': 'Your password has been reset',
            'PASSWORD_CHANGE_NOTICE': 'Your password has been changed',
            'FORGOT_PASS': 'Password reset instructions',
        },
        'EMAIL_HTML_TEMPLATE':{
            'REGISTER': 'protect/email/welcome.html',
            'CONFIRM_INSTRUCTIONS': 'protect/email/confirm_email.html',
            'PASSWORD_RESET_NOTICE': 'protect/email/notice.html',
            'PASSWORD_CHANGE_NOTICE': 'protect/email/notice.html',
            'FORGOT_PASS': 'protect/email/reset_instructions.html',
        },
        'EMAIL_TXT_TEMPLATE':{
            'REGISTER': 'protect/email/welcome.txt',
            'CONFIRM_INSTRUCTIONS': 'protect/email/confirm_email.txt',
            'PASSWORD_RESET_NOTICE': 'protect/email/notice.txt',
            'PASSWORD_CHANGE_NOTICE': 'protect/email/notice.txt',
            'FORGOT_PASS': 'protect/email/reset_instructions.txt',
        },
        'EMAIL_BODY':{
            'REGISTER': 'Welcome!',
            'CONFIRM_INSTRUCTIONS': 'Please confirm your email address!',
            'PASSWORD_RESET_NOTICE': 'Your password has recently been reset!',
            'PASSWORD_CHANGE_NOTICE': 'Your password has recently been changed',
            'FORGOT_PASS': 'To reset your password...',
        },
        'CRYPT_SETTINGS':{
            'schemes':[
                'bcrypt',
                'sha256_crypt',
                'sha512_crypt',
                'des_crypt',
                'pbkdf2_sha256',
                'pbkdf2_sha512',
                # And always last one...
                'plaintext'
            ],
            'default': 'sha256_crypt',
            'deprecated':["auto"], #By Default, Depreciate all schemes except default
            'truncate_error':False #Silently truncate password.
            },
        'URLS': {
            'LOGIN':'/login',
            'LOGOUT':'/logout',
            'REGISTER':'/register',
            'FORGOT_PASS':'/forgot_password',
            'RESET_PASS': '/reset_password',
            'CHANGE_PASS':'/change_password',
            'CONFIRM_EMAIL':'/confirm_account'
            },
        'TEMPLATES': {
            'LOGIN': 'protect/form_template.html',
            'REGISTER': 'protect/form_template.html',
            'FORGOT_PASS': 'protect/form_template.html',
            'RESET_PASS': 'protect/form_template.html',
            'CHANGE_PASS': 'protect/form_template.html',
            'CONFIRM_EMAIL': 'protect/form_template.html',
        },
        'FORMS':{
            'LOGIN': LoginForm,
            'REGISTER': RegisterIdentifierForm,
            'FORGOT_PASS': ForgotPasswordForm,
            'RESET_PASS': ResetPasswordForm,
            'CHANGE_PASS': ChangePasswordForm,
            'CONFIRM_EMAIL': ConfirmEmailForm
            },
        'REDIRECT':{
            'LOGIN': '',
            'LOGOUT': '',
            'REGISTER': '',
            'FORGOT_PASS': '',
            'RESET_PASS': '',
            'CHANGE_PASS': '',
            'CONFIRM_EMAIL': ''
            },
        'ACTIONS':{
            'LOGIN': login,
            'LOGOUT': None,
            'REGISTER': register,
            'FORGOT_PASS': forgot_password,
            'RESET_PASS':reset_password,
            'CHANGE_PASS': change_password,
            'CONFIRM_EMAIL': ''
        },
        'SALT':{
            'FORGOT_PASS': 'forgot-pass-salt',
            'CONFIRM_SALT': 'confirm-salt',
            'RESET_SALT': 'reset-salt',
            'LOGIN_SALT': 'login-salt',
            'CHANGE_SALT': 'change-salt',
            'REMEMBER_SALT': 'remember-salt'
        },
        'MSGS': {
            'BAD_USER_PASS':('Invalid Username or password.', 'error'),
            'BAD_EMAIL_PASS':('Invalid Email Address or Password.','error'),
            #TODO: Filter through and remove unneeded messages
            'UNAUTHORIZED': (
                ('You do not have permission to view this resource.'), 'error'),
            'CONFIRM_REGISTRATION': (
                ('Thank you. Confirmation instructions '
                  'have been sent to %(email)s.'),
                'success'),
            'EMAIL_CONFIRMED': (
                ('Thank you. Your email has been confirmed.'), 'success'),
            'ALREADY_CONFIRMED': (
                ('Your email has already been confirmed.'), 'info'),
            'INVALID_CONFIRMATION_TOKEN': (
                ('Invalid confirmation token.'), 'error'),
            'EMAIL_ALREADY_ASSOCIATED': (
                ('%(email)s is already associated with an account.'), 'error'),
            'PASSWORD_MISMATCH': (
                ('Password does not match'), 'error'),
            'RETYPE_PASSWORD_MISMATCH': (
                ('Passwords do not match'), 'error'),
            'INVALID_REDIRECT': (
                ('Redirections outside the domain are forbidden'), 'error'),
            'PASSWORD_RESET_REQUEST': (
                ('Instructions to reset your password have been sent to %(email)s.'),
                'info'),
            'PASSWORD_RESET_EXPIRED': (
                ('You did not reset your password within %(within)s. '
                  'New instructions have been sent to %(email)s.'), 'error'),
            'INVALID_RESET_PASSWORD_TOKEN': (
                ('Invalid reset password token.'), 'error'),
            'CONFIRMATION_REQUIRED': (
                ('Email requires confirmation.'), 'error'),
            'CONFIRMATION_REQUEST': (
                ('Confirmation instructions have been sent to %(email)s.'), 'info'),
            'CONFIRMATION_EXPIRED': (
                ('You did not confirm your email within %(within)s. '
                  'New instructions to confirm your email have been sent '
                  'to %(email)s.'), 'error'),
            'LOGIN_EXPIRED': (
                ('You did not login within %(within)s. New instructions to login '
                  'have been sent to %(email)s.'), 'error'),
            'LOGIN_EMAIL_SENT': (
                ('Instructions to login have been sent to %(email)s.'), 'success'),
            'INVALID_LOGIN_TOKEN': (
                ('Invalid login token.'), 'error'),
            'DISABLED_ACCOUNT': (
                ('Account is disabled.'), 'error'),
            'EMAIL_NOT_PROVIDED': (
                ('Email not provided'), 'error'),
            'INVALID_EMAIL_ADDRESS': (
                ('Invalid email address'), 'error'),
            'PASSWORD_NOT_PROVIDED': (
                ('Password not provided'), 'error'),
            'PASSWORD_NOT_SET': (
                ('No password is set for this user'), 'error'),
            'PASSWORD_INVALID_LENGTH': (
                ('Password must be at least 6 characters'), 'error'),
            'USER_DOES_NOT_EXIST': (
                ('Specified user does not exist'), 'error'),
            'INVALID_PASSWORD': (
                ('Invalid password'), 'error'),
            'PASSWORDLESS_LOGIN_SUCCESSFUL': (
                ('You have successfully logged in.'), 'success'),
            'FORGOT_PASSWORD': (
                ('Forgot password?'), 'info'),
            'PASSWORD_RESET': (
                ('You successfully reset your password and you have been logged in '
                  'automatically.'), 'success'),
            'PASSWORD_IS_THE_SAME': (
                ('Your new password must be different than your previous password.'),
                'error'),
            'PASSWORD_CHANGE': (
                ('You successfully changed your password.'), 'success'),
            'LOGIN': (
                ('Please log in to access this page.'), 'info'),
            'REFRESH': (
                ('Please reauthenticate to access this page.'), 'info')
        },
        'FORM_FIELDS':{
            'USER_ID': 'user_id',
            'IDENTIFIER':'identifier',
            'EMAIL':'email_address',
            'PASSWORD':'password',
            'CURRENT_PASSWORD': 'current_password',
            'REMEMBER_ME':'remember',
        },
        'USER_FIELDS':{
            'IDENTIFIER':'username',
            'EMAIL':'email_address',
            'PASSWORD':'password'
        }
    }

    def __init__(self, datastore, login_manager=None, crypt_context=None, **kwargs):
        super().__init__(datastore=datastore, login_manager=login_manager, crypt_context=crypt_context, **kwargs)
    #
    #   Validator Functions
    #
    def get_user(self, identifier):
        if isinstance(identifier, self._datastore.UserModel):
            return identifier
        user=None
        if isinstance(identifier, int):
            user = self._datastore.get_user_by_id(identifier)
        if not user and ( ( self.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') and not user ) or self.config_or_default('USE_EMAIL_AS_ID') ):
            user = self._datastore.get_user_by_email(identifier)
        #If allowing both email and username and user not already found by email, OR not using email
        if not user and ( ( self.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') and not user ) or not self.config_or_default('USE_EMAIL_AS_ID') ):
            user = self._datastore.get_user_by_identifier(identifier)
        return user

    def get_user_from_form(self, form):
        user_identifier=None
        if self.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') or self.config_or_default('USE_EMAIL_AS_ID'):
            field = self.get_field(form, 'EMAIL')
            if field:
                user_identifier = field.data
        #If allowing both email and username and user not already found by email, OR not using email
        if ( self.config_or_default('ALLOW_BOTH_IDENTIFIER_AND_EMAIL') and not user_identifier ) or not self.config_or_default('USE_EMAIL_AS_ID'):
            field = self.get_field(form, 'IDENTIFIER')
            if field:
                user_identifier = field.data
        if not user_identifier:
            field = self.get_field(form, 'USER_ID')
            if field:
                user_identifier = int(field.data)
        try:
            return self.get_user(identifier=user_identifier)
        except:
            return None

    def create_user(self, **kwargs):
        kwargs['password'] = self.hash_password(kwargs['password'])
        return self._datastore.create_user(**kwargs)

    def validate_user(self, identifier, password, **kwargs):
        user = self.get_user(identifier)
        valid=False
        new_hash=None
        if user:
            if self.config_or_default('AUTO_UPDATE_HASH'):
                valid, new_hash = self.validate_password_and_update_hash(password, user.password, **kwargs)
            else:
                valid = self.validate_password(password, user.password, **kwargs)
            if valid and new_hash:
                self._datastore.update_password_hash(user, new_hash)
        else:
            self.dummy_validate()
        return valid

    def change_user_password(self, identifier, current_password, new_password):
        user = self.get_user(identifier)
        if self.validate_user(user, current_password):
            self.reset_user_password(user, new_password)
            return True
        return False

    def reset_user_password(self, identifier, new_password):
        user = self.get_user(identifier)
        self._datastore.update_user_password(user, self.hash_password(new_password))

    def send_reset_password_instructions(self, user):
        context={'user':user, 'code':self.generate_code(user, 'FORGOT_PASS') }
        self.send_mail('FORGOT_PASS', user, context=context)

    def send_comfirm_email_instructions(self, user):
        context={'user':user, 'code':self.generate_code(user, 'CONFIRM_EMAIL') }
        self.send_mail('CONFIRM_EMAIL', user, context=context)

    def send_password_reset_notification(self, user, content):
        context={'user':user, 'code':self.generate_code(user, 'PASSWORD_RESET') }
        self.send_mail('PASSWORD_RESET', user, context=context)

    def send_password_change_notification(self, user, content):
        context={'user':user, 'code':self.generate_code(user, 'PASSWORD_CHANGE') }
        self.send_mail('PASSWORD_CHANGE', user, context=context)
    #
    #   Other Utilites
    #
    def get_user_from_token_data(self, token, invalid=False):
        user = self.get_user(int(token[0]))
        if not invalid and user:
            if not self.validate_password(user.password, token[1]):
                invalid=True
        return user, invalid

    def generate_code(self, user, action):
        password_hash = self.hash(user.password) if user.password else None
        data = [str(user.id), password_hash]
        return self.generate_token(action, data)

    def send_mail(self, action, user, **context):
        if self.config_or_default('SEND_EMAIL'):
            mail=current_app.extensions.get('mail')
            subject=_validator.config_or_default('EMAIL_SUBJECT')[action]
            recipient=getattr(user, self.get_user_field('EMAIL'))
            msg = Message(subject=subject, sender=self.config_or_default('EMAIL_SENDER'), recipients=[recipient])
            if self.config_or_default('EMAIL_PLAINTEXT'):
                template=self.config_or_default('EMAIL_TXT_TEMPLATE')[action]
                msg.body=render_template(template, **context)
            if self.config_or_default('EMAIL_HTML'):
                template=self.config_or_default('EMAIL_HTML_TEMPLATE')[action]
                msg.html=render_template(template, **context)
            mail.send(msg)
    #
    #   View Methods
    #
    def view(self, action, **kwargs):
        form, validated = self.get_and_validate_form(action, **kwargs)
        if validated:
            action_func = self.get_action_config(action)
            if action_func(form):
                redirect_url = get_redirect_url(self.get_redirect_config(action))
                return redirect(redirect_url)
        template = self.get_template_config(action)
        return render_template(template, layout=self.config_or_default('LAYOUT_TEMPLATE'), form=form)

    def login_view(self):
        if self._login_manager.user_is_anonymous_user():
            return self.view('LOGIN')
        else:
            redirect_url = get_redirect_url(self.get_redirect_config('LOGIN'))
            return redirect(redirect_url)

    def register_view(self):
        if self._login_manager.user_is_anonymous_user():
            return self.view('REGISTER')
        else:
            redirect_url = get_redirect_url(self.get_redirect_config('LOGIN'))
            return redirect(redirect_url)

    def forgot_pass_view(self):
        if self._login_manager.user_is_anonymous_user():
            form, validated = self.get_and_validate_form('FORGOT_PASS')
            if validated:
                action_func = self.get_action_config('FORGOT_PASS')
                reset_code = self.generate_code(self.get_user_from_form(form), 'RESET_SALT')
                if action_func(form):
                    if self.config_or_default('FORGOT_PASS_DIRECT_TO_RESET_PASS'):
                        return redirect(url_for_protect('reset_password', reset_code=reset_code))
                    else:
                        redirect_url = get_redirect_url(self.get_redirect_config('FORGOT_PASS'))
                        return redirect(redirect_url)
            template = self.get_template_config('FORGOT_PASS')
            return render_template(template, layout=self.config_or_default('LAYOUT_TEMPLATE'), form=form)
            if self.config_or_default('FORGOT_PASS_DIRECT_TO_RESET_PASS'):
                return redirect(url_for_protect('reset_password'))
        else:
            redirect_url = get_redirect_url(self.get_redirect_config('LOGIN'))
            return redirect(redirect_url)

    def change_pass_view(self):
        self._login_manager.user_is_authenticated()
        return self.view('CHANGE_PASS')

    def logout_view(self):
        self._login_manager.user_is_authenticated()
        action_func = self.get_action_config('LOGOUT')
        if action_func:
            action_func()
        self.logout_user()
        redirect_url = get_redirect_url(self.get_redirect_config('LOGOUT'))
        return redirect(redirect_url)

    def reset_pass_view(self, reset_code=None):
        if not self._login_manager.user_is_anonymous_user():
            redirect_url = get_redirect_url(self.get_redirect_config('LOGIN'))
            return redirect(redirect_url)
        #If valid code for forgotten password:
        expired, invalid, data = self.load_token(token=reset_code, serializer_name='RESET_SALT')
        user, invalid = self.get_user_from_token_data(data, invalid)
        if not user or invalid:
            invalid = True
            #Display Message that code is invalid
        if user and expired:
            #Resend instruction and try again
            self.send_reset_password_instructions(user)
        if invalid or expired:
            return redirect(url_for_protect('forgot_password'))
        return self.view('RESET_PASS', **{'user_id': user.id})

    def confirm_email_view(self, confirm_code):
        if not self._login_manager.user_is_anonymous_user():
            redirect_url = get_redirect_url(self.get_redirect_config('LOGIN'))
            return redirect(redirect_url)
        #If valid code for Confirmation
        expired, invalid, data = self.load_token(token=confirm_code, serializer_name='CONFIRM_EMAIL')
        user, invalid = self.get_user_from_token_data(data, invalid)
        #else Error!

    #
    #   Blueprint Section
    #
    def routes(self, blueprint):
        blueprint.add_url_rule(rule=self.get_url_config('LOGIN'), endpoint='login', view_func=self.login_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('REGISTER'), endpoint='register', view_func=self.register_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('LOGOUT'), endpoint='logout', view_func=self.logout_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('CHANGE_PASS'), endpoint='change_password', view_func=self.change_pass_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('FORGOT_PASS'), endpoint='forgot_password', view_func=self.forgot_pass_view, methods=['GET', 'POST'])
        blueprint.add_url_rule(rule=self.get_url_config('RESET_PASS')+'/<string:reset_code>', endpoint='reset_password', view_func=self.reset_pass_view, methods=['GET', 'POST'])
        #blueprint.add_url_rule(rule=self.get_url_config('CONFIRM_EMAIL')+'/<string:confirm_code>', endpoint='confirm_email', view_func=self.confirm_email_view, methods=['GET', 'POST'])

    def initialize(self, app, blueprint, **kwargs):
        super().initialize(app, blueprint, **kwargs)
        if not app.extensions.get('mail'):
            self._config['SEND_EMAIL']=False

    def get_defaults(self):
        return self.__DEFAULT_CONFIG
