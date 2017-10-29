import string
import jsonfield
import operator
from functools import reduce
from django.db.models import Q
from django.utils import timezone
from django.apps import apps
from django.db import models
from django.dispatch import receiver
from django.db import IntegrityError
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.core.validators import MinValueValidator
from phonenumber_field.modelfields import PhoneNumberField

from network_monitor.helpers.shortcuts import get_installed_features
from network_monitor.helpers.utils import SafeFormat, MACAddressField, find_mac_manufacture

SEVERITY_CLEAR = 0
SEVERITY_DEBUG = 1
SEVERITY_INFO = 2
SEVERITY_WARNING = 3
SEVERITY_ERROR = 4
SEVERITY_CRITICAL = 5

SEVERITY_CHOICES = (
    (SEVERITY_CRITICAL, 'Critical'),
    (SEVERITY_ERROR, 'Error'),
    (SEVERITY_WARNING, 'Warning'),
    (SEVERITY_INFO, 'Info'),
    (SEVERITY_DEBUG, 'Debug'),
    (SEVERITY_CLEAR, 'Clear'),
)


class Device(models.Model):
    STATUS_UP = 'up'
    STATUS_DOWN = 'down'
    STATUS_CHOICES = (
        (STATUS_UP, 'Up'),
        (STATUS_DOWN, 'Down'),
    )

    name = models.CharField("Name", max_length=256, unique=True)
    address = models.GenericIPAddressField("IP Address")
    web_port = models.PositiveSmallIntegerField("Web Port", null=True, blank=True)
    mac = MACAddressField('Mac Address', null=True, blank=True, unique=True)
    mac_manufacture = models.CharField(max_length=128, null=True, blank=True)
    username = models.CharField("Username", max_length=128, null=True,
                                blank=True)
    password = models.CharField("Password", max_length=128, null=True,
                                blank=True)
    location = models.CharField("Location", max_length=512,
                                null=True, blank=True)
    purchase_date = models.DateField(null=True, blank=True)
    manufacture_date = models.DateField(null=True, blank=True)
    warranty_expiration_date = models.DateField(null=True, blank=True)
    note = models.TextField("Note", null=True, blank=True)
    status = models.CharField('Status', max_length=16, choices=STATUS_CHOICES, default=STATUS_DOWN)
    tags = models.CharField('Tags', max_length=1024, blank=True, null=True, default=None)
    last_seen = models.DateTimeField("Last Seen", null=True)
    created = models.DateTimeField("Created At", auto_now_add=True)
    active = models.BooleanField("Active", default=True)

    @classmethod
    def secret_fields(self):
        return ['password']

    @property
    def active_features(self):
        return [f.feature for f in self.feature.filter(active=True).order_by('feature')]

    @property
    def status_display(self):
        return dict(self.STATUS_CHOICES).get(self.status, self.STATUS_DOWN)

    @property
    def web_url(self):
        return 'http://{}{}'.format(self.address, ':{}'.format(self.web_port) if self.web_port else '')

    def fetch_mac_manufacture(self, abort=False):
        if not self.mac:
            return
        return find_mac_manufacture(self.mac, abort=abort)

    class Meta:
        permissions = (
            ('access_device_secret_data', 'Can access device secret data'),
            ('ping_test_device', 'Can send ping test for device'),
        )

    def save(self, *args, **kwargs):
        if self.mac == '':
            self.mac = None
        return super(Device, self).save(*args, **kwargs)

    def __str__(self):
        return self.name.capitalize()


class DeviceFeature(models.Model):
    FEATURE_CHOICES = tuple([(a, a) for a in get_installed_features()])
    device = models.ForeignKey(Device, on_delete=models.CASCADE,
                               related_name='feature')
    feature = models.CharField('Feature Name', max_length=128,
                               choices=FEATURE_CHOICES)
    round_interval = models.PositiveIntegerField(
        "Round Interval(Seconds)", blank=False, null=False, default=60,
        validators=[MinValueValidator(1)])
    last_round = models.DateTimeField('Last Round', blank=True,
                                      null=True)
    active = models.BooleanField("Enabled?", default=False)
    args = jsonfield.JSONField('Feature Args', null=False, blank=True,
                               default=dict)
    conf = jsonfield.JSONField('Feature Conf', null=False, blank=True,
                               default=dict)

    class Meta:
        unique_together = (("device", "feature"),)

    @property
    def app_feature(self):
        return apps.get_app_config(self.feature)

    def __str__(self):
        return '{}(device={})'.format(self.feature, self.device)


class Threshold(models.Model):

    device_feature = models.ForeignKey(DeviceFeature, on_delete=models.CASCADE,
                                       related_name='threshold')
    name = models.CharField('Name', max_length=128)
    type = models.CharField('Type', max_length=128)
    severity = models.SmallIntegerField('Severity', choices=SEVERITY_CHOICES,
                                        default=SEVERITY_INFO)
    trigger_time = models.DateTimeField("Trigger Time", null=True)
    clear_time = models.DateTimeField("Clear Time", null=True)
    active = models.BooleanField("Active?", default=True)
    data = jsonfield.JSONField('Data', null=False, blank=False,
                               default=dict)

    @property
    def severity_display(self):
        return dict(SEVERITY_CHOICES).get(self.severity)

    def trigger(self):
        self.trigger_time = timezone.now()
        self.clear_time = None

    def clear(self):
        self.clear_time = timezone.now()

    @property
    def threshold_object(self):
        from network_monitor.monit_manager.threshold import Manager
        th_cls = Manager.get_threshold_cls(self.type)
        args = self.data.get('args', ())
        kwargs = self.data.get('kwargs', {})
        return th_cls(*args, **kwargs)

    def __str__(self):
        return self.name


class Event(models.Model):

    device = models.ForeignKey(Device, on_delete=models.CASCADE,
                               related_name='event', null=True)
    threshold = models.ForeignKey(Threshold, on_delete=models.SET_NULL,
                                  related_name='event', null=True)
    feature = models.CharField('Feature Name', max_length=128, null=True)
    severity = models.SmallIntegerField('Severity', choices=SEVERITY_CHOICES,
                                        default=SEVERITY_INFO)
    summary = models.CharField('Summary', max_length=512, null=True)
    message = models.TextField('Message', max_length=10240)
    first_time = models.DateTimeField('First Time', auto_now_add=True)
    last_time = models.DateTimeField('Last Time', default=timezone.now)
    count = models.PositiveIntegerField("Count", default=1)
    clear_time = models.DateTimeField("Clear Time", null=True)
    notify_time = models.DateTimeField("Notify Time", null=True)
    seen = models.BooleanField("Seen?", default=False)

    @property
    def severity_display(self):
        return dict(SEVERITY_CHOICES).get(self.severity)

    def clear(self):
        self.clear_time = timezone.now()

    @classmethod
    def create_or_update(cls, **kwargs):
        if kwargs.get('threshold'):
            args = dict(
                clear_time=None,
                severity=kwargs.pop('severity', SEVERITY_INFO),
                threshold=kwargs.pop('threshold', None),
                device=kwargs.pop('device', None),
                feature=kwargs.pop('feature', None),
            )
            kwargs.pop('clear_time', None)
            obj = cls.objects.filter(**args).first()
            if not obj:
                args.update(kwargs)
                obj = cls.objects.create(**args)
            else:
                obj.last_time = timezone.now()
                obj.count += 1
                obj.save()
        else:
            obj = cls.objects.create(**kwargs)

        return obj

    def save(self, *args, **kwargs):
        if self.severity == SEVERITY_CLEAR and self.clear_time is None:
            self.clear()
        return super(Event, self).save(*args, **kwargs)

    def __str__(self):
        return '{} Event({})'.format(self.severity_display, self.summary)


class UserProfile(models.Model):
    user = models.OneToOneField(User, related_name="profile",
                                on_delete=models.CASCADE)
    sms_number = PhoneNumberField(blank=True, null=True)

    def __str__(self):
        return '{}'.format(self.user)


class RuleComilerException(Exception):
    pass


class RulesCompiler(object):
    OPERATORS = dict(
        eq=lambda f, v: Q(**{f: v}),
        neq=lambda f, v: ~Q(**{f: v}),
        gt=lambda f, v: Q(**{f+'__gt': v}),
        gte=lambda f, v: Q(**{f+'__gte': v}),
        lt=lambda f, v: Q(**{f+'__lt': v}),
        lte=lambda f, v: Q(**{f+'__lte': v}),
        contains=lambda f, v: Q(**{f+'__contains': v}),
        icontains=lambda f, v: Q(**{f+'__icontains': v}),
        startswith=lambda f, v: Q(**{f+'__startswith': v}),
        endswith=lambda f, v: Q(**{f+'__endswith': v}),
    )

    def __init__(self, rules):
        self.rules = rules
        assert rules, 'rules cannot be empty'

    def compile(self):
        q_list = []
        rule_conditions = self.rules.get('conditions')
        join_by = operator.or_ if self.rules.get('join_by') == 'or'\
            else operator.and_
        for rule in rule_conditions:
            try:
                op = rule['o']
                parameter = rule['p']
                value = rule['v']
            except KeyError:
                raise RuleComilerException('Invalid rule')
            if op not in self.OPERATORS:
                raise RuleComilerException('Invalid operator')
            q = self.OPERATORS[op](parameter, value)
            q_list.append(q)

        return reduce(join_by, q_list)


MEDIA_SMS = 'sms'
MEDIA_EMAIL = 'email'
MEDIA_WEB = 'web'
MEDIA_CHOICES = (
    (MEDIA_SMS, 'SMS'),
    (MEDIA_EMAIL, 'Email'),
    (MEDIA_WEB, 'Web Dashboard'),
)


class UserAlertRule(models.Model):
    DEFAULT_MESSAGE = '<p>Device: {device_name}<p>{event_message}</p>'
    DEFAULT_SUMMARY = '{event_summary}'
    name = models.CharField('Name', max_length=128)
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name='alert_rule')
    active = models.BooleanField("Enabled?", default=True)
    notify_media = jsonfield.JSONField('Notify by', null=False, blank=False)
    rules = jsonfield.JSONField('Rules', null=False, blank=False)
    custom_message = models.TextField('Custom Message', max_length=10240, blank=True, null=True)
    custom_summary = models.TextField('Custom Summary', max_length=512, blank=True, null=True)

    def get_message_context(self, event):
        device = event.device
        threshold = event.threshold
        return {
            'device_name': device and device.name,
            'device_address': device and device.address,
            'threshold_name': threshold and threshold.name,
            'threshold_type': threshold and threshold.type,
            'feature': event.feature,
            'event_severity': event.severity_display,
            'event_summary': event.summary,
            'event_message': event.message,
            'event_time': event.first_time,
        }

    def get_message_by_event(self, event):
        message_template = (self.custom_message or '').strip() or self.DEFAULT_MESSAGE
        context = self.get_message_context(event)
        return string.Formatter().vformat(message_template, [], SafeFormat(**context))

    def get_summary_by_event(self, event):
        summary_template = (self.custom_summary or '').strip() or self.DEFAULT_SUMMARY
        context = self.get_message_context(event)
        return string.Formatter().vformat(summary_template, [], SafeFormat(**context))

    @property
    def notify_media_display(self):
        return dict(MEDIA_CHOICES).get(self.notify_media)

    def is_triggered_event(self, event):
        rc = RulesCompiler(self.rules)
        query = rc.compile()
        return Event.objects.filter(id=event.id).filter(query).count() > 0

    def get_triggered_events(self):
        rc = RulesCompiler(self.rules)
        query = rc.compile()
        return Event.objects.exclude(seen=True).filter(query).all()

    def save(self, *args, **kwargs):
        valid_media = [m[0] for m in MEDIA_CHOICES]
        if not isinstance(self.notify_media, (list, tuple)) or \
                any(n not in valid_media for n in self.notify_media):
            raise IntegrityError('Invalid value of notify_media')

        return super(UserAlertRule, self).save(*args, **kwargs)

    def __str__(self):
        return self.name


class AlertNotification(models.Model):
    STATUS_SENT = 'sent'
    STATUS_FAILED = 'failed'
    STATUS_RECEIVED = 'received'
    STATUS_CHOICES = (
        (STATUS_SENT, 'Sent'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_RECEIVED, 'Received'),
    )

    status = models.CharField('Status', max_length=32, default=STATUS_SENT,
                              choices=STATUS_CHOICES)
    notify_media = models.CharField('Notify Type', max_length=32,
                                    choices=MEDIA_CHOICES)
    subject = models.CharField('Subject', max_length=128, blank=True,
                               null=True)
    message = models.TextField('Message', blank=False, null=False)

    notify_datetime = models.DateTimeField('Notify Date/Time', blank=True,
                                           null=True, default=timezone.now)
    received_datetime = models.DateTimeField('Received Date/Time', blank=True,
                                             null=True)
    user = models.ForeignKey(User, related_name="alert_notification",
                             null=True, on_delete=models.CASCADE)
    severity = models.SmallIntegerField('Severity', choices=SEVERITY_CHOICES,
                                        default=SEVERITY_INFO)

    def received(self):
        self.received_datetime = timezone.now()
        self.status = self.STATUS_RECEIVED

    @property
    def notify_media_display(self):
        return dict(MEDIA_CHOICES).get(self.notify_media)

    def __str__(self):
        return '#{}'.format(self.pk)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
