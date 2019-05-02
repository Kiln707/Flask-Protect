from flask import current_app
from werkzeug.local import LocalProxy
try:
    from urlparse import urlsplit
except ImportError:  # pragma: no cover
    from urllib.parse import urlsplit

_protect = LocalProxy(lambda: current_app.extensions['protect'])
_validator = LocalProxy(lambda: _protect._validator)
_datastore = LocalProxy(lambda: _validator._datastore)

def url_for_protect(endpoint, **kwargs):
    #Return a URL for Protect blueprint
    endpoint = '%s.%s' % (_protect.config('BLUEPRINT_NAME'), endpoint)
    return url_for(endpoint, **values)

def validate_redirect_url(url):
    if url is None or url.strip() == '':
        return False
    url_next = urlsplit(url)
    url_base = urlsplit(request.host_url)
    if (url_next.netloc or url_next.scheme) and \
            url_next.netloc != url_base.netloc:
        return False
    return True
