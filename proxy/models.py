from django.db import models
from django.contrib.postgres.fields import JSONField
from . import helper


class RewriteRules(models.Model):
    url = models.CharField(max_length=1024, validators=[helper.validate_regex_string])
    headers = JSONField(default={})
    response = models.TextField(default='')
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
