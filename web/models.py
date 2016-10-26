from django.contrib.postgres.fields import JSONField
from django.db import models

from . import helper


class RewriteRules(models.Model):
    url = models.CharField(max_length=1024, validators=[helper.validate_regex_string], blank=True)
    headers = JSONField(default={}, blank=True)
    response = models.TextField(default='', blank=True)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
