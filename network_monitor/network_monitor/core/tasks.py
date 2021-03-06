from __future__ import absolute_import

import random
import subprocess
from datetime import timedelta

from django.db.models import Q
from dynamic_preferences.registries import global_preferences_registry

try:
    from network_monitor.helpers.utils import py2_subprocess_run as subprocess_run
except ImportError:
    from subprocess import run as subprocess_run
from network_monitor.helpers.utils import scan_network_ips
from bs4 import BeautifulSoup
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


@celery_app.task()
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


@celery_app.task()
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


@celery_app.task(ignore_result=True, soft_time_limit=settings.REDIS_MEM_DEFAULT_EXPIRE)
def nmap_scan_network(user_id, ip_range):
    logger.info('++++++++++++++ Start Scanning network [%s] by [%s] ...', ip_range, user_id)
    redis_mem = get_redis_mem('nmap_scan_network')
    try:
        scan = scan_network_ips(ip_range)
        redis_mem.set(str(user_id), {'ip_range': ip_range, 'success': True, 'result': scan})
    except Exception as e:
        redis_mem.set(str(user_id), {'ip_range': ip_range, 'success': False, 'errors': e.args})
        logger.exception('UnExpected Exception')
    finally:
        logger.info('++++++++++++++ Finished Scanning network [%s] by [%s] ...', ip_range, user_id)


def create_unique_device(name, **kwargs):
    counter = 1
    while True:
        if Device.objects.filter(name=name).count() > 0:
            name = '{}.{}'.format(name, counter)
            counter += 1
        else:
            break
    device = Device(name=name, **kwargs)
    device.mac_manufacture = device.fetch_mac_manufacture()
    device.save()
    return device

def _check_discovered_devices(scan, auto_add_new=True):
    for ip, data in scan.items():
        logger.info('*** Checking device with ip: [%s]', ip)
        mac = data.get('vendor', {}).get('mac')
        hostnames = [d.get('name') for d in data.get('hostnames', []) if d.get('name')]
        if not mac:
            logger.warning('!!! Unknown mac for device with ip: %s', ip)
            continue
        device = Device.objects.filter(mac=mac).first()
        if device and (device.address != ip):
            device.address = ip
            device.active = True
            device.save(update_fields=['address', 'active'])
            logger.info('*** assigned new ip for device <%s: %s>.', device.id, device)
        elif (not device) and auto_add_new:
            name = '{} - Auto'.format(hostnames[0] if hostnames else ip)
            device = create_unique_device(name, address=ip, mac=mac)
            logger.info('*** created new device %s. [ip=%s mac=%s]', device, device.address, device.mac)
        if device and not device.active:
            device.active = True
            device.save(update_fields=['active'])


def _check_disabled_devices(auto_disable_after):
    disable_after = timedelta(days=auto_disable_after)
    max_last_seen = timezone.now() - disable_after
    devices = Device.objects.filter(Q(last_seen__isnull=True) & Q(created__lt=max_last_seen)|
                                    Q(last_seen__isnull=False) & Q(last_seen__lt=max_last_seen),
                                    active=True)
    devices_count = devices.count()
    if devices_count > 0:
        logger.info('!!! [%s] idle devices found to be archived!', devices_count)
        devices.update(active=False)


@celery_app.task()
def dhcp_scan_devices():
    global_preferences = global_preferences_registry.manager()
    logger.info('+ Start DHCP Scanning network ...')
    enabled_dhcp = global_preferences['dhcp_scan__is_enabled']
    if not enabled_dhcp:
        logger.info('!!! Stopped Scanning! DHCP Scan is Disabled !!!')
        return
    ip_ranges = global_preferences['dhcp_scan__ip_ranges']
    if not ip_ranges:
        logger.info('!!! Stopped Scanning! No ip_ranges set in dhcp_scan settings !!!')
        return
    ip_ranges = [ip_range.strip() for ip_range in ip_ranges.split(',')]
    auto_add_new = global_preferences['dhcp_scan__auto_add_new']
    for ip_range in ip_ranges:
        logger.info('*** Scanning ip range: [%s] ...', ip_range)
        scan = scan_network_ips(ip_range)
        logger.info('*** Checking [%s] discovered devices in range [%s] ...', len(scan), ip_range)
        _check_discovered_devices(scan, auto_add_new=auto_add_new)

    logger.info('*** Checking to disable/archive not seen devices ...')
    auto_disable_after = global_preferences['dhcp_scan__auto_disable_after']
    if auto_disable_after:
        _check_disabled_devices(auto_disable_after)

    logger.info('+++ Finished DHCP Scanning network ...')
