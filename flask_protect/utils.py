from flask import current_app, request, session, after_this_request, url_for
from werkzeug.local import LocalProxy

import datetime
from itsdangerous import URLSafeTimedSerializer

from ._compat import urlsplit, urlparse

_protect = LocalProxy(lambda: current_app.extensions['protect'])

url_for_protect = LocalProxy(lambda: _protect.url_for)

def get_url(endpoint_or_url):
    try:
        return url_for(endpoint_or_url)
    except:
        return endpoint_or_url


# def is_safe_url(url, allowed_hosts, require_https=False):
#     """
#     Return ``True`` if the url is a safe redirection (i.e. it doesn't point to
#     a different host and uses a safe scheme).
#
#     Always return ``False`` on an empty url.
#
#     If ``require_https`` is ``True``, only 'https' will be considered a valid
#     scheme, as opposed to 'http' and 'https' with the default, ``False``.
#     """
#     if url is not None:
#         url = url.strip()
#     if not url:
#         return False
#     if allowed_hosts is None:
#         allowed_hosts = set()
#     # Chrome treats \ completely as / in paths but it could be part of some
#     # basic auth credentials so we need to check both URLs.
#     return (_is_safe_url(url, allowed_hosts, require_https=require_https) and
#             _is_safe_url(url.replace('\\', '/'), allowed_hosts, require_https=require_https))

# def _is_safe_url(url, allowed_hosts, require_https=False):
#     # Chrome considers any URL with more than two slashes to be absolute, but
#     # urlparse is not so flexible. Treat any url with three slashes as unsafe.
#     if url.startswith('///'):
#         return False
#     try:
#         url_info = _urlparse(url)
#     except ValueError:  # e.g. invalid IPv6 addresses
#         return False
#     # Forbid URLs like http:///example.com - with a scheme, but without a hostname.
#     # In that URL, example.com is not the hostname but, a path component. However,
#     # Chrome will still consider example.com to be the hostname, so we must not
#     # allow this syntax.
#     if not url_info.netloc and url_info.scheme:
#         return False
#     # Forbid URLs that start with control characters. Some browsers (like
#     # Chrome) ignore quite a few control characters at the start of a
#     # URL and might consider the URL as scheme relative.
#     if unicodedata.category(url[0])[0] == 'C':
#         return False
#     scheme = url_info.scheme
#     # Consider URLs without a scheme (e.g. //example.com/p) to be http.
#     if not url_info.scheme and url_info.netloc:
#         scheme = 'http'
#     valid_schemes = ['https'] if require_https else ['http', 'https']
#     return ((not url_info.netloc or url_info.netloc in allowed_hosts) and
#             (not scheme or scheme in valid_schemes))


def is_safe_url(url, allowed_hosts=set(), external='', require_https=False, allow_userpass=False, allowed_schemes=['http', 'https']):
    def safe(url, allowed_hosts, external, require_https, allow_userpass, allowed_schemes):
        import unicodedata
        # Chrome considers any URL with more than two slashes to be absolute, but
        # urlparse is not so flexible. Treat any url with three slashes as unsafe.
        if url.startswith('///'):
            return False
        try:
            url_info = urlparse(url)
        except ValueError:  # e.g. invalid IPv6 addresses
            return False
        # Forbid URLs like http:///example.com - with a scheme, but without a hostname.
        if not url_info.netloc and url_info.scheme:
            return False

        # Forbid URLs that start with control characters. Some browsers (like
        # Chrome) ignore quite a few control characters at the start of a
        # URL and might consider the URL as scheme relative.
        if unicodedata.category(url[0])[0] == 'C':
            return False

        scheme = url_info.scheme
        # Consider URLs without a scheme (e.g. //example.com/p) to be http.
        if not url_info.scheme and url_info.netloc:
            scheme = 'http'
        if require_https and url_info.scheme != 'https':
            return False




        return ((not url_info.netloc or url_info.netloc in allowed_hosts) and
                (not scheme or scheme in valid_schemes))

        print("url: ", url)
        print("scheme: ",url_info.scheme) #will need to check
        print("netloc: ",url_info.netloc)
        print("path: ",url_info.path) #If @ in path, no prepended scheme
        print("params: ",url_info.params) #Sub-pages
        print("query: ",url_info.query) #Will leave alone
        print("fragment: ",url_info.fragment) #Safe, internal page reference (AKA Anchors)
        print("username: ",url_info.username) # Will discourage, but make allowable to use username, password
        print("password: ",url_info.password)
        print("hostname: ",url_info.hostname) # Will need to validate
        print("port: ",url_info.port) #Safe, will ignore
        print("---------------------------------------")
        return True
    if url is not None:
        url = url.strip()
    if not url:
        return False
    # If url is not an actual url, but an endpoint
    # It is safe to trust.
    try:
        current_app.url_map.iter_rules(url)
        return True
    except KeyError:
        return ((safe(url, allowed_hosts, external, require_https, allow_userpass, allowed_schemes)) and (safe(url.replace('\\','/'), allowed_hosts, external, require_https, allow_userpass, allowed_schemes)))

#
#   Next Parameter methods
#

#   Cookie Next
def set_session_next(next_url):
    session['next'] = next_url

def get_session_next(save=False):
    next = None
    if save:
        next = session.get('next', None)
    else:
        next = session.pop('next', None)
    return next

#   Request Next
def get_request_next():
    try:
        return request.args['next']
    except:
        return None

#   Form Next
def get_request_form_next():
    try:
        return request.form['next']
    except:
        return None

def get_redirect_url(default, additional_urls=[]):
    urls = [
        get_url(get_session_next()),
        get_url(get_request_next()),
        get_url(get_request_form_next()),
        get_url(default)
    ]
    if additional_urls:
        urls.insert(0, additional_urls)
    for url in urls:
        if is_safe_url(url):
            return url
    return None
