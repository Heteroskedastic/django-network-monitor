# -*- coding: utf-8 -*-
# Generated by Django 1.9.9 on 2017-01-02 08:17
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_auto_20170101_1623'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicefeature',
            name='last_round',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Last Round'),
        ),
    ]
