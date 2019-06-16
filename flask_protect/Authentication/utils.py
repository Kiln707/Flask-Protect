from werkzeug.local import LocalProxy

from ..utils import _protect, _validator, _datastore

def get_field(form, key):
    if hasattr(form, _validator.get_form_field_config(key)):
        return getattr(form, _validator.get_form_field_config(key))
    elif hasattr(form, key):
        return getattr(form, key)
    return None
