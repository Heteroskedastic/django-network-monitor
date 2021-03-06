# -*- coding: utf-8 -*-
# Generated by Django 1.9.9 on 2016-12-31 12:44
from __future__ import unicode_literals

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import jsonfield.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Device',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=256, verbose_name='Name')),
                ('address', models.CharField(max_length=256, unique=True, verbose_name='Address(uri or ip)')),
                ('title', models.CharField(blank=True, max_length=256, null=True, verbose_name='Title')),
                ('mac', models.CharField(blank=True, max_length=17, null=True, verbose_name='Mac Address')),
                ('location', models.CharField(blank=True, max_length=512, null=True, verbose_name='Location')),
                ('note', models.TextField(blank=True, null=True, verbose_name='Note')),
                ('status', models.CharField(choices=[('up', 'Up'), ('down', 'Down'), ('unknown', 'Uknown')], default='unknown', max_length=16, verbose_name='Status')),
                ('active', models.BooleanField(default=True, verbose_name='Active')),
            ],
        ),
        migrations.CreateModel(
            name='DeviceFeature',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('feature', models.CharField(choices=[('ping', 'ping')], max_length=128, verbose_name='Feature Name')),
                ('check_interval', models.PositiveIntegerField(default=60, validators=[django.core.validators.MinValueValidator(1)], verbose_name='Check Interval(Seconds)')),
                ('active', models.BooleanField(default=False, verbose_name='Active')),
                ('args', jsonfield.fields.JSONField(default=dict, verbose_name='Feature Args')),
                ('conf', jsonfield.fields.JSONField(default=dict, verbose_name='Feature Conf')),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='feature', to='core.Device')),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='devicefeature',
            unique_together=set([('device', 'feature')]),
        ),
    ]
