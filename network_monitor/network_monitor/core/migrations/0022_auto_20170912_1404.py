# -*- coding: utf-8 -*-
# Generated by Django 1.9.9 on 2017-09-12 14:04
from __future__ import unicode_literals

from django.db import migrations
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0021_auto_20170405_0636'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='device',
            options={'permissions': (('access_device_secret_data', 'Can access device secret data'), ('ping_test_device', 'Can send ping test for device'))},
        ),
        migrations.AlterField(
            model_name='devicefeature',
            name='args',
            field=jsonfield.fields.JSONField(blank=True, default=dict, verbose_name='Feature Args'),
        ),
        migrations.AlterField(
            model_name='devicefeature',
            name='conf',
            field=jsonfield.fields.JSONField(blank=True, default=dict, verbose_name='Feature Conf'),
        ),
    ]
