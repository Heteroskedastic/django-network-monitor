# -*- coding: utf-8 -*-
# Generated by Django 1.9.9 on 2017-10-29 15:31
from __future__ import unicode_literals

from django.db import migrations, models
import django.utils.timezone
import network_monitor.helpers.utils


def forwards_func(apps, schema_editor):
    db_alias = schema_editor.connection.alias
    Device = apps.get_model("core", "Device")
    for device in Device.objects.using(db_alias).filter(mac=''):
        device.mac = None
        device.save(update_fields=["mac"])


def reverse_func(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0022_auto_20170912_1404'),
    ]

    operations = [
        migrations.RunPython(forwards_func, reverse_func),
        migrations.AddField(
            model_name='device',
            name='created',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now, verbose_name='Created At'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='device',
            name='mac',
            field=network_monitor.helpers.utils.MACAddressField(blank=True, max_length=17, null=True, unique=True,
                                                                verbose_name='Mac Address'),
        ),
    ]