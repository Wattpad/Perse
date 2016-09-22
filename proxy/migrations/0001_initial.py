# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2016-09-21 00:19
from __future__ import unicode_literals

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import proxy.helper


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='RewriteRules',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.CharField(max_length=1024, validators=[proxy.helper.validate_regex_string])),
                ('headers', django.contrib.postgres.fields.jsonb.JSONField(default={})),
                ('response', models.TextField(default=b'')),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('modified_date', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
