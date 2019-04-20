def url_for_protect(endpoint, **kwargs):
    #Return a URL for Protect blueprint
    endpoint = '%s.%s' % (_security.blueprint_name, endpoint)
    return url_for(endpoint, **values)
