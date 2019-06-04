from flask import current_app, request, session, after_this_request
from werkzeug.local import LocalProxy

import datetime
from itsdangerous import URLSafeTimedSerializer

from ._compat import urlsplit

_protect = LocalProxy(lambda: current_app.extensions['protect'])
_validator = LocalProxy(lambda: _protect._validator)
_datastore = LocalProxy(lambda: _validator._datastore)

def url_for_protect(endpoint, **kwargs):
    #Return a URL for Protect blueprint
    endpoint = '%s.%s' % (_protect.config('BLUEPRINT_NAME'), endpoint)
    return url_for(endpoint, **values)

def get_url(endpoint_or_url):
    try:
        return url_for(endpoint_or_url)
    except:
        return endpoint_or_url

def safe_url(url):
    if url is None or url.strip() == '':
        return False
    url_next = urlsplit(url)
    url_base = urlsplit(request.host_url)
    if (url_next.netloc or url_next.scheme) and \
            url_next.netloc != url_base.netloc:
        return False
    return True

#
#   Next Parameter methods
#
def _clear_cookie_next(self):
    session.pop('request', None)

def set_cookie_next(self, next_url):
    session['next'] = next_url
    after_this_request(self._clear_cookie_next)

def set_request_next(self, next_url):
    setattr(request.args, 'next', next_url)

def _get_cookie_next(self):
    if 'next' in session:
        return session['next']
    return None

def _get_request_args_next(self):
    if request.args and hasattr(request.args, 'next'):
        return getattr(request.args, 'next')
    return None

def _get_request_form_next(self):
    if request.form and hasattr(request.form, 'next'):
        return getattr(request.form, 'next')
    return None

def get_redirect(self, default, additional_urls=[]):
    urls = [
        get_url(_get_cookie_next()),
        get_url(_get_request_args_next()),
        get_url(_get_request_form_next()),
        get_url(default)
    ]
    if additional_urls:
        urls.insert(0, additional_urls)
    for url in urls:
        if safe_url(url):
            return url
    return None


#
#   TimeDelta utils
#
def get_within_delta(time):
    if isinstance(time, datetime.timedelta):
        return time.seconds + time.days * 24 * 3600
    elif str(time):
        values = time.split()
        td = timedelta(**{values[1]: int(values[0])})
        return td.seconds + td.days * 24 * 3600
    raise TypeError()
