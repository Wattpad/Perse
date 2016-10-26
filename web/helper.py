import json
import re

from django.core.exceptions import ValidationError


def get_url_header_name():
    return 'HTTP_URL'


def get_headers_header_name():
    return 'HTTP_HEADERS'


def get_use_regex_header_name():
    return 'HTTP_USE_REGEX'


def format_header_keys(headers, as_json_string=False):
    """
    Returns a str or dict of {header_key: header_value, ...}, where each header_key is lowercased and its
    hyphens are replaced with underscores.

    :param headers: header dict
    :param as_json_string: if True, will return a json string, otherwise return a dict
    :return: copy of the header dict with modified keys (as dict or str, depending on `as_json_string`)
    """
    new_headers = {k.lower().replace('-', '_'): v for k, v in headers.iteritems()}
    if as_json_string:
        return json.dumps(new_headers)
    return new_headers


def get_request_headers(req_headers, use_default_values=False, as_json_string=False):
    """
    Returns a tuple of (url=str/None, headers=dict/str/None, use_regex=str/None) from the request headers.

    :param req_headers: the request headers (i.e. request.META)
    :param use_default_values: if True, will return default values if certain request headers are empty, else None
    :param as_json_string: if True, will return the `headers` (i.e. index 1) as a JSON string instead of dict
    :return: a tuple. None will be used if `use_default_values` == False and if a key is missing from the headers
    """
    headers = req_headers.get(get_headers_header_name(), '{}' if use_default_values else None)
    return (req_headers.get(get_url_header_name(), '.*' if use_default_values else None),
            format_header_keys(json.loads(headers), as_json_string) if headers is not None else None,
            req_headers.get(get_use_regex_header_name(), '1' if use_default_values else None))


def validate_regex_string(string):
    try:
        re.compile(string)
    except re.error:
        raise ValidationError("{} is not a valid regex string".format(string))
