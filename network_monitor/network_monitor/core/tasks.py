from __future__ import absolute_import

import subprocess
try:
    from network_monitor.helpers.utils import py2_subprocess_run as subprocess_run
except ImportError:
    from subprocess import run as subprocess_run
from bs4 import BeautifulSoup
from celery.decorators import periodic_task
from datetime import timedelta
from django.utils import timezone, six
from django.core.mail import send_mail
from django.conf import settings
from celery.utils.log import get_task_logger

from network_monitor.core.models import DeviceFeature, Device, AlertNotification, \
    UserAlertRule, Event, MEDIA_SMS, MEDIA_EMAIL, MEDIA_WEB
from network_monitor import celery_app
from network_monitor.helpers.shortcuts import get_redis_mem
from network_monitor.helpers.utils import send_sms


logger = get_task_logger(__name__)


def _send_mail(subject, message, email, silent=True):
    from_email = settings.DEFAULT_EMAIL_FROM
    recipient_list = [email] if isinstance(email, six.string_types) else list(email)
    logger.info('Sending email to %s', email)
    send_mail(
        subject, message, from_email, recipient_list,
        html_message=message, fail_silently=silent)


def strip_message(message):
    if message:
        message = BeautifulSoup(
            message, "html.parser").get_text(separator="\n")
    return message


def send_event_by_rule(event, rule):
    if isinstance(event, int):
        event = Event.objects.get(id=event)
    if isinstance(rule, int):
        rule = UserAlertRule.objects.get(id=rule)
    user = rule.user
    email = user.email
    sms_number = user.profile.sms_number
    summary = rule.get_summary_by_event(event)
    message = rule.get_message_by_event(event)
    for media in rule.notify_media:
        alert = AlertNotification(notify_media=media, user=user,
                                  severity=event.severity)
        if media == MEDIA_EMAIL:
            if not email:
                logger.warning('No email for user %s', user)
                continue
            logger.info('Sending email to %s', email)
            _send_mail(summary, message, email, silent=True)
            alert.subject = summary
            alert.message = message

        elif media == MEDIA_SMS:
            if not sms_number:
                logger.warning('No sms_number for user %s', user)
                continue
            logger.info('Sending sms to %s', sms_number)
            safe_message = strip_message(message)
            send_sms(safe_message, sms_number)
            alert.subject = summary
            alert.message = safe_message
        elif media == MEDIA_WEB:
            alert.subject = summary
            alert.message = message
        else:
            logger.warning('Invalid media %s', media)
            continue
        alert.save()
    event.notify_time = timezone.now()
    event.save(update_fields=["notify_time"])


@periodic_task(run_every=timedelta(minutes=2), ignore_result=True)
def check_alert_rules_periodic():
    '''
    check user alert rules to notify
    python manage.py celeryd -B -l info
    '''
    rules = UserAlertRule.objects.filter(active=True).order_by('id').all()
    if len(rules) == 0:
        logger.warning('!!!! No rules triggered!')
        return
    for rule in rules:
        events = rule.get_triggered_events()
        logger.info('!!!! [%s] events found for rule %s!', len(events), rule)
        for event in events:
            send_event_by_rule(event, rule)
    Event.objects.exclude(seen=True).update(seen=True)


@periodic_task(run_every=timedelta(minutes=5), ignore_result=True)
def check_device_status_periodic():
    '''
    check connection status of devices
    python manage.py celeryd -B -l info
    '''
    devices = Device.objects.order_by('id').all()
    logger.info('>>>> Checking status of [%s] devices', len(devices))
    for device in devices:
        if not device.active:
            if device.status != Device.STATUS_DOWN:
                device.status = device.STATUS_DOWN
                device.save(update_fields=["status"])
            continue

        cmd = "/bin/ping -n -q -c 1 -W 1 {address}".format(address=device.address)
        logger.info('>>>> Ping Command is: %s', cmd)
        result = subprocess_run(cmd, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        output = result.stdout.decode()
        err = result.stderr.decode()
        if not output:
            logger.error(err)
            continue
        elif '100% packet loss' in output:
            device.status = device.STATUS_DOWN
        else:
            device.status = device.STATUS_UP
            device.last_seen = timezone.now()
        device.save(update_fields=["status", "last_seen"])


def _feature_mon_handle(df):
    MonHandlerClass = getattr(df.app_feature, 'mon_handler_class', None)
    if not MonHandlerClass:
        logger.warning('No MonHandler class for feature %s', df.feature)
        return
    handler = MonHandlerClass(device_feature=df, logger=logger)
    logger.info('****** Running a round for %s *******', df)
    handler.handle()


@celery_app.task(ignore_result=True)
def feature_mon_handle(df_id):
    logger.info('++++++++++++++ Start Checking for ID #%s...', df_id)
    df = DeviceFeature.objects.filter(id=df_id).first()
    if not df:
        logger.warning('device feature with id %s does not exists!', df_id)
        return
    try:
        _feature_mon_handle(df)
    except Exception:
        logger.exception('UnExpected Exception')
    finally:
        df.last_round = timezone.now()
        df.save(update_fields=["last_round"])
        logger.info('++++++++++++++ Finished Checking for ID #%s...', df_id)
        redis_mem = get_redis_mem('feature_mon_handle')
        redis_mem.delete(str(df_id))
