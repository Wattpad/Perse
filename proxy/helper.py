import json
import re

from django.core.exceptions import ValidationError


def get_url_header_name():
    return 'HTTP_URL'


def get_headers_header_name():
    return 'HTTP_HEADERS'


def get_no_regex_header_name():
    return 'HTTP_NO_REGEX'


def get_all_from_request_headers(req_headers, use_default_values=False):
    """
    Returns a tuple of (url=str/None, headers=dict/None, no_regex=str/None)

    :param req_headers: the request headers (i.e. request.META)
    :param use_default_values: if True, will return default values if certain request headers are empty, else None
    :return: a tuple. None will be used if `use_default_values` == False and if a key is missing from the headers
    """
    headers = req_headers.get(get_headers_header_name(), '{}' if use_default_values else None)
    return (req_headers.get(get_url_header_name(), '.*' if use_default_values else None),
            json.loads(headers) if headers is not None else None,
            req_headers.get(get_no_regex_header_name(), '0' if use_default_values else None))


def validate_regex_string(string):
    try:
        re.compile(string)
    except re.error:
        raise ValidationError("{} is not a valid regex string".format(string))
