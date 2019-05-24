from werkzeug.local import LocalProxy

from ..utils import _protect, _validator, _datastore

def get_field(form, key):
    if hasattr(form, key):
        return getattr(form, _validator.config_or_default(key))
    return None
