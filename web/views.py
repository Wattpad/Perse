import json
import re

from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.shortcuts import render
from rest_framework.decorators import api_view

from .models import RewriteRules
from . import helper


@api_view(['GET'])
def index(request):
    entries = RewriteRules.objects.all().order_by('-modified_date')
    return render(request, 'web/index.html', {'entries': entries})


@api_view(['GET'])
def fetch(request):
    """
    Returns the database entry's `response` value, when the request headers match all of the following:
    - `url`
    - `headers`

    :param request: django request
    :return: HttpResponse with the response stored in the database
    """
    if request.method == 'GET':
        url, headers, use_regex = helper.get_all_from_request_headers(request.META)

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
    - (optional): `use-regex`: 0 if the values stored in `headers` are exact strings
                               1 if the values stored in `headers` are regex strings (default)

    The request body be encoded as application/json and must include:
    - {"response": JSON} - if the response value is a string, it will be unicode. Otherwise it will be encoded in utf-8.

    :param request: django request
    """
    if request.method == 'POST':
        url, headers, use_regex = helper.get_all_from_request_headers(request.META, use_default_values=True)
        try:
            custom_response = request.data['response']
            if type(custom_response) in (dict, list):
                # store as a json string
                custom_response = json.dumps(custom_response, ensure_ascii=False).encode('utf-8')
        except:
            return HttpResponse('Requires `Content-Type=application/json` in the request headers and '
                                '{"response": `response_json/string`} in request body.', status=400)

        if use_regex == '0':
            # exact match string, but still using regex
            headers = {k: '^{}$'.format(re.escape(v)) for k, v in headers.iteritems()}

        # validate header regex
        for header in headers:
            try:
                helper.validate_regex_string(headers[header])
            except ValidationError:
                return HttpResponse("'{}' is not a valid regex string.".format(headers[header]), status=400)

        if RewriteRules.objects.filter(url=url, headers=headers):
            entry = RewriteRules.objects.get(url=url, headers=headers)
            entry.response = custom_response
            entry.full_clean()
            entry.save()
            return HttpResponse(status=201)
        else:
            entry = RewriteRules(url=url, headers=headers, response=custom_response)
            entry.full_clean()
            entry.save()
            return HttpResponse(status=201)


@api_view(['POST'])
def delete(request):
    """
    Deletes the database entry matching all the following request headers:
    - `url`
    - `headers`

    :param request: django request
    """
    if request.method == 'POST':
        url, headers, use_regex = helper.get_all_from_request_headers(request.META)

        if url is not None and headers is not None:
            entry = RewriteRules.objects.get(url=url, headers=headers)
            entry.delete()
            return HttpResponse(status=204)
        else:
            return HttpResponse(status=400)


@api_view(['POST'])
def delete_id(request):
    """
    Deletes the database entry matching all of the following request body args:
    - `id`

    :param request: django request
    """
    if request.method == 'POST':
        id_ = request.data.get('id')
        if id_:
            entry = RewriteRules.objects.get(id=id_)
            entry.delete()
            return HttpResponse(status=204)
        return HttpResponse(status=400)
