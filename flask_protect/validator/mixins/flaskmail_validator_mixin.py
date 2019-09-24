from .validator_base import ValidatorMixin

class FMail_Mixin(ValidatorMixin):
    def send_mail(self, action, user, **context):
        mail=current_app.extensions.get('mail')
        if mail:
            subject=_validator.get_config('EMAIL_SUBJECT')[action]
            recipient=getattr(user, self.get_user_field('EMAIL'))
            msg = Message(subject=subject, sender=self.get_config('EMAIL_SENDER'), recipients=[recipient])
            if self.get_config('EMAIL_PLAINTEXT'):
                template=self.get_config('EMAIL_TXT_TEMPLATE')[action]
                msg.body=render_template(template, **context)
            if self.get_config('EMAIL_HTML'):
                template=self.get_config('EMAIL_HTML_TEMPLATE')[action]
                msg.html=render_template(template, **context)
            mail.send(msg)
