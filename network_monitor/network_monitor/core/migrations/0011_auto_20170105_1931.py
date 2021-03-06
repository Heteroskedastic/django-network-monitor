# -*- coding: utf-8 -*-
# Generated by Django 1.9.9 on 2017-01-05 19:31
from __future__ import unicode_literals

from django.db import migrations
import django.utils.timezone


def forwards_func(apps, schema_editor):
    db_alias = schema_editor.connection.alias
    Event = apps.get_model("core", "Event")
    for event in Event.objects.using(db_alias).all():
        event.seen = True
        event.save()


def reverse_func(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0010_auto_20170105_1923'),
    ]

    operations = [
        migrations.RunPython(forwards_func, reverse_func),
    ]
