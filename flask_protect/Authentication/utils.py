from werkzeug.local import LocalProxy

from ..utils import _protect

_validator = LocalProxy(lambda: _protect._validator)
_datastore = LocalProxy(lambda: _validator._datastore)
