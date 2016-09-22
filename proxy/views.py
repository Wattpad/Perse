import re

from django.http import HttpResponse
from rest_framework.decorators import api_view

from .models import RewriteRules
from . import helper


@api_view(['GET', 'POST'])
def fetch(request):
    """
    Returns the database entry's `response` value, when the request headers match all of the following:
    - `url`
    - `headers`

    :param request: django request
    :return: HttpResponse with the response stored in the database
    """
    if request.method in ('GET', 'POST'):
        url, headers, no_regex = helper.get_all_from_request_headers(request.META)

        if url is not None and headers is not None:
            entry = RewriteRules.objects.get(url=url, headers=headers)
            if entry:
                return HttpResponse(entry.response)
            return HttpResponse(status=404)
        return HttpResponse(status=400)


@api_view(['POST'])
def store(request):
    """
    Stores a custom response based on matching rules.
    Note: Django stores all headers with hyphens replaced with underscores and case does not matter.
    (https://docs.djangoproject.com/en/1.10/ref/request-response/#django.http.HttpRequest.META)

    The request header must include:
    - (optional) `url`=regex string (default='.*')
        e.g. ".*google\.(ca|com)\/$"
    - (optional) `headers`=json, where key=header name, value=regex (default='{}')
        e.g. {'User-Agent': '.*Chrome.*', 'Accept-Language': 'en\-US'}
        Note: the key is case insensitive, and the value is case sensitive unless you prepend '(?i)' for regex strings
    - (optional): `no-regex`: 1 if the values stored in `headers` are NOT regex strings (default='0')
                              (may be useful if you want to store exact strings)

    The request body be encoded as application/json and must include:
    - {"response": string}

    :param request: django request
    """
    if request.method == 'POST':
        url, headers, no_regex = helper.get_all_from_request_headers(request.META, use_default_values=True)
        custom_response = request.data['response']

        if no_regex == '1':
            headers = {k: '^{}$'.format(re.escape(v)) for k, v in headers.iteritems()}

        if RewriteRules.objects.filter(url=url, headers=headers):
            entry = RewriteRules.objects.get(url=url, headers=headers)
            entry.response = custom_response
            entry.full_clean()
            entry.save()
            return HttpResponse(status=204)
        else:
            entry = RewriteRules(url=url, headers=headers, response=custom_response)
            entry.full_clean()
            entry.save()
            return HttpResponse(status=204)


@api_view(['POST'])
def delete(request):
    """
    Deletes the database entry matching all the following request headers:
    - `url`
    - `headers`

    :param request: django request
    """
    if request.method == 'POST':
        url, headers, no_regex = helper.get_all_from_request_headers(request.META)

        if url is not None and headers is not None:
            entry = RewriteRules.objects.get(url=url, headers=headers)
            entry.delete()
            return HttpResponse(status=204)
        else:
            return HttpResponse(status=400)
