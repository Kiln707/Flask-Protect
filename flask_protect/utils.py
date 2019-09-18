from flask import current_app, request, session, after_this_request, url_for
from werkzeug.local import LocalProxy

import datetime, socket, unicodedata
from itsdangerous import URLSafeTimedSerializer

from ._compat import urlsplit, urlparse

_protect = LocalProxy(lambda: current_app.extensions['protect'])

url_for_protect = LocalProxy(lambda: _protect.url_for)

def get_url(endpoint_or_url):
    try:
        return url_for(endpoint_or_url)
    except:
        return endpoint_or_url

class UnsafeURLError(Exception):
    code_msg = {
    0: 'No URL present',
    1: 'Invalid characters in URL',
    2: 'Unsafe browser behavior with starting ///',
    3: 'Invalid IP Address',
    4: 'No hostname with scheme and path',
    5: 'Starts with unicode control character, causes undetermined behavior',
    6: 'HTTPS required! URL has unallowed scheme',
    7: 'URL has unallowed scheme',
    8: 'URL contains username and/or password which was not allowed',
    9: 'URL contains unallowed hostname'
    }
    def __init__(self, code):
        self.code = code
        self.message = self.code_msg[code]

def valid_ipv6(address):
    # From Joe Hildebrand and the Tin man
    # https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False

def is_safe_url(url, allowed_hosts=[], require_https=False, allow_userpass=False, allowed_schemes=['http', 'https'], pass_Exception=False):
    def safe(url):
        # Chrome considers any URL with more than two slashes to be absolute, but
        # urlparse is not so flexible. Treat any url with three slashes as unsafe.
        if url.startswith('///'):
            return (False, UnsafeURLError(2)) if pass_Exception else False
        try:
            url_info = urlparse(url)
        except ValueError:  # e.g. invalid IPv6 addresses
            return (False, UnsafeURLError(3)) if pass_Exception else False
        print(url_info)
        # Forbid URLs like http:///example.com - with a scheme, but without a hostname.
        if not url_info.netloc and url_info.scheme:
            return (False, UnsafeURLError(4)) if pass_Exception else False
        # Forbid URLs that start with control characters. Some browsers (like
        # Chrome) ignore quite a few control characters at the start of a
        # URL and might consider the URL as scheme relative.
        if unicodedata.category(url[0])[0] == 'C':
            return (False, UnsafeURLError(5)) if pass_Exception else False
        scheme = url_info.scheme
        # Consider URLs without a scheme (e.g. //example.com/p) to be http or https.
        if not scheme and url_info.netloc:
            scheme = 'https' if require_https else 'http'
        # Fail if https is required and scheme is not https or not allowed scheme
        if require_https and scheme != 'https':
            return (False, UnsafeURLError(6)) if pass_Exception else False
        elif scheme and scheme not in allowed_schemes:
            return (False, UnsafeURLError(7)) if pass_Exception else False
        # If we don't want to allow username/passwords in the url, ensure there is no username/password
        if not allow_userpass and (url_info.username or url_info.password):
            return (False, UnsafeURLError(8)) if pass_Exception else False
        host_url = urlparse(request.host_url)
        hostname = url_info.hostname

        # If IPv6 is used, ensure it is grabbed
        if '@' in url_info.netloc:
            netloc_split = url_info.netloc.split('@')[1]
        else:
            netloc_split = url_info.netloc
        netloc_split = netloc_split.split('.')
        for partial in netloc_split:
            if valid_ipv6(partial):
                hostname = '.'.join(netloc_split)

        # If the path contains the actual hostname (Or what would be treated as hostname), set hostname to path
        if not hostname and ( '.' in url_info.path and not url_info.path.startswith( ('.', '/', ';', '#', '?') ) ):
            hostname = url_info.path
        # return whether this url hostname is this server OR is one of the allowed hostnames
        if hostname and not (hostname == host_url.hostname or hostname in allowed_hosts):
            print(hostname, hostname in allowed_hosts)
            return (False, UnsafeURLError(9)) if pass_Exception else False
        # Relative Path is safe
        return (True, None) if pass_Exception else True
    if url is not None:
        url = url.strip()
    if not url:
        return (False, UnsafeURLError(0)) if pass_Exception else False
    # If url is not an actual url, but an endpoint
    # It is safe to trust.
    try:
        current_app.url_map.iter_rules(url)
        return (True, None) if pass_Exception else True
    except KeyError:
        if any( chr in url for chr in ('<', '>', '`', '^')):
            return (False, UnsafeURLError(1)) if pass_Exception else False
        return (safe(url) and safe(url.replace('\\','/')))

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
