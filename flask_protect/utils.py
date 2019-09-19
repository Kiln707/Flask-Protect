from flask import current_app, request, session, after_this_request, url_for
from werkzeug.local import LocalProxy

import datetime, socket, unicodedata
from ipaddress import ip_address
from itsdangerous import URLSafeTimedSerializer
from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6
from sys import platform

from ._compat import urlsplit, urlparse

_protect = LocalProxy(lambda: current_app.extensions['protect'])

url_for_protect = LocalProxy(lambda: _protect.url_for)

def get_url(endpoint_or_url):
    try:
        return url_for(endpoint_or_url)
    except:
        return endpoint_or_url

def valid_ipv6(address):
    # From Joe Hildebrand and the Tin man
    # https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False

def valid_ipv4(address):
    # From Joe Hildebrand and the Tin man
    # https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except socket.error:
        return False

def _local_ip4_addresses():
    # From rahul
    # https://stackoverflow.com/questions/49195864/how-to-get-all-ip-addresses-using-python-windows
    '''
    Gathers and returns a list of all ipv4 addresses
    assigned to all interfaces of the local machine
    '''
    ip_list = []
    for interface in interfaces():
        for link in ifaddresses(interface)[AF_INET]:
            if 'addr' in link:
                ip_list.append(link['addr'])
    return ip_list

def _local_ip6_addresses():
    # From rahul; Edited by Steven Swanson
    # https://stackoverflow.com/questions/49195864/how-to-get-all-ip-addresses-using-python-windows
    '''
    Gathers and returns a list of all ipv6 addresses
    assigned to all interfaces of the local machine
    '''
    ip_list = []
    for interface in interfaces():
        for link in ifaddresses(interface)[AF_INET6]:
            if 'addr' in link:
                ip_list.append(link['addr'])
    return ip_list

def get_local_hostnames():
    '''
    Gathers all domain names and ip_addresses
    that reference this local machine
    '''
    host_url = set(urlparse(request.host_url).hostname)
    for ip in _local_ip4_addresses():
        host_url.add(ip)
    for ip in _local_ip6_addresses():
        host_url.add(ip)
    host_url.add(socket.getfqdn())
    return list(host_url)

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

def is_safe_url(url, allowed_hosts=[], require_https=False, allow_userpass=False, allowed_schemes=['http', 'https'], pass_Exception=False):
    def iphostname_in_allowed_hosts(hostname=[]):
        ip = ip_address(hostname[len(hostname)-1])
        for allowhost in allowed_hosts:
            allowhost = allowhost.split('.')
            end = len(allowhost)-1
            if not ( valid_ipv4(allowhost[end]) or valid_ipv6(allowhost[end]) ): #only check ipaddresses
                continue
            allowhost[end] = ip_address(allowhost[end])
            if allowhost[end] != ip:    #If the ipaddress is not correct, dont bother checking it all
                continue
            if len(allowhost) != len(hostname): #If lengths are different then different number of subdomains, cannot match
                continue
            cont = False
            for i in range(0, end):
                if allowhost[i] != hostname[i]:
                    cont = True
                    break
            if cont:
                continue
            return True
        return False

    def safe(url):
        # Chrome considers any URL with more than two slashes to be absolute, but
        # urlparse is not so flexible. Treat any url with three slashes as unsafe.
        if url.startswith('///'):
            return (False, UnsafeURLError(2)) if pass_Exception else False
        try:
            url_info = urlparse(url)
        except ValueError:  # e.g. invalid IPv6 addresses
            return (False, UnsafeURLError(3)) if pass_Exception else False
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

        username=''
        password=''
        # If IP is used, ensure it is grabbed
        # If username/password is hidden in netloc, extract it
        if '@' in url_info.netloc:
            netloc_split = url_info.netloc.split('@')
            if ':' in netloc_split[0]:
                s = netloc_split[0].split(':')
                username = s[0]
                password = s[1]
            else:
                username = netloc_split[0]
            netloc_split = netloc_split[1]
        # Username not in netloc, just grab netloc
        # Assign username/password from url_info, if there
        else:
            netloc_split = url_info.netloc
            username = url_info.username
            password = url_info.password
        # We should have username/password now regardless if it was set correctly by urlparse
        # If we don't want to allow username/passwords in the url, ensure there is no username/password
        if not allow_userpass and (username or password):
            return (False, UnsafeURLError(8)) if pass_Exception else False
        #Set hostname to hostname, if there. May not consistently get an IPaddress
        hostname = url_info.hostname
        ip = ''
        # If there is an ipaddress it may not be set correctly by urlparse
        # extract ipaddress and any subdomains and set hostname to it.
        netloc_split = netloc_split.split('.')
        ipstr = netloc_split[len(netloc_split)-1] # Extract the last item, as IP is always at end of hostname
        if valid_ipv4(ipstr) or valid_ipv6(ipstr):
            ip = ip_address(ipstr)
            hostname = '.'.join(netloc_split)
            netloc_split[len(netloc_split)-1]  = ip

        # If the path contains the actual hostname (Or what would be treated as hostname), set hostname to path
        if not hostname and ( '.' in url_info.path and not url_info.path.startswith( ('.', '/', ';', '#', '?') ) ):
            hostname = url_info.path
        # return whether this url hostname is this server OR is one of the allowed hostnames
        localhostnames = get_local_hostnames()
        if hostname and not (hostname in localhostnames or hostname in allowed_hosts):
            if ip:
                # For cases where host is a subdomain of an ipaddress such as www.192.168.0.1
                # Extract ips of localhost and see if hostname matches the ip address
                # in an actiual IpAddress Object made to handle ip addresses.
                for localhost in localhostnames:
                    if not ( valid_ipv4(localhost) or valid_ipv6(localhost) ):
                        continue
                    localip = ip_address(localhost)
                    if localip != ip:
                        continue
                    else:
                        if hostname == str(ip) or hostname == str(ip.exploded):
                            return (True, None) if pass_Exception else True
                        # If we find that the hostname IP Address matches one of localhosts ip addresses
                        # then we will check to see if it matches a hostname with that IPaddress with
                        # listed subdomains
                        if iphostname_in_allowed_hosts(netloc_split):
                            # If match is found, then subdomain @ ipaddress is authorized
                            return (True, None) if pass_Exception else True
                        #No match was found, subdomain not authorized
                        break
                # Other external IP / Subdomain+IP
                if iphostname_in_allowed_hosts(netloc_split):
                    # If match is found, then subdomain @ ipaddress is authorized
                    return (True, None) if pass_Exception else True
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
    for url in additional_urls:
        urls.insert(0,url)
    for url in urls:
        if is_safe_url(url):
            return url
    return None
