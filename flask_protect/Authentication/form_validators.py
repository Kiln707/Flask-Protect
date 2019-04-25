from builtins import object
from ..utils import _protect

class FormValidatorMixin(object):
    def __call__(self, form, field):
        if self.message and self.message.isupper():
            self.message = _protect.get_message(self.message)[0]
        return super(FormValidatorMixin, self).__call__(form, field)
