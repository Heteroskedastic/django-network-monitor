# -*- coding: utf-8 -*-
# Generated by Django 1.9.9 on 2017-02-23 17:06
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0018_auto_20170208_0728'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='web_port',
            field=models.PositiveSmallIntegerField(blank=True, null=True, verbose_name='Web Port'),
        ),
    ]