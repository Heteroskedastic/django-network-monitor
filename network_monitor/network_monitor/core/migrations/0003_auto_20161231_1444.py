# -*- coding: utf-8 -*-
# Generated by Django 1.9.9 on 2016-12-31 14:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_auto_20161231_1440'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='address',
            field=models.CharField(max_length=256, verbose_name='Address(uri or ip)'),
        ),
    ]
