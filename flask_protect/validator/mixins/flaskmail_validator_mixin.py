from .validator_base import ValidatorMixin

class FMail_Mixin(ValidatorMixin):
    def send_mail(self, recipients, sender, subject, template, plaintext=True, html=True, **context):
        mail=current_app.extensions.get('mail')
        if mail:
            msg=Message(subject=subject, sender=from, recipients=recipients)
            if plaintext:
                msg.body=render_template(template, **context)
            if html:
                msg.html=render_template(template, **context)
            mail.send(msg)
