class FMail_Mixin():
    def send_mail(self, action, user, **context):
        mail=current_app.extensions.get('mail')
        if mail:
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
