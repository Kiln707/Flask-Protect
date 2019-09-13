from flask import current_app, request, session, after_this_request, url_for
from werkzeug.local import LocalProxy

import datetime
from itsdangerous import URLSafeTimedSerializer

from ._compat import urlsplit

_protect = LocalProxy(lambda: current_app.extensions['protect'])

url_for_protect = LocalProxy(lambda: _protect.url_for)

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

#   Cookie Next
def _clear_cookie_next():
    session.pop('next', None)

def set_cookie_next(next_url):
    session['next'] = next_url
    after_this_request(_clear_cookie_next)

def get_cookie_next():
    if 'next' in session:
        return session['next']
    return None

#   Request Next
def get_request_next():
    try:
        return request.args['next']
    except:
        return None

#   Form Next
def get_request_form():
    return request.form

def get_request_form_next():
    try:
        return request.form['next']
    except:
        return None

def get_redirect_url(default, additional_urls=[]):
    urls = [
        get_url(get_cookie_next()),
        get_url(get_request_args_next()),
        get_url(get_request_form_next()),
        get_url(default)
    ]
    if additional_urls:
        urls.insert(0, additional_urls)
    for url in urls:
        if safe_url(url):
            return url
    return None
