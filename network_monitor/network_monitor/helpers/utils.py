import re
import nmap
import arpreq
import random
import string
import decimal
import datetime
import subprocess

import requests
from django.utils.translation import ugettext_lazy as _
from django.forms import fields
from django.db import models
from django.contrib import messages
from django.shortcuts import render
from django.http import JsonResponse, Http404
from django.utils import six
from django.core.urlresolvers import reverse
from django.utils.safestring import mark_safe
from django.utils.dateparse import parse_datetime
from django.utils.timezone import is_aware, make_aware
from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.contrib.auth.mixins import PermissionRequiredMixin as \
    DjangoPermissionRequiredMixin

from network_monitor.helpers.shortcuts import get_twilio_client


def random_id(n=8, no_upper=False, no_lower=False, no_digit=False):
    rand = random.SystemRandom()
    chars = ''
    if no_upper is False:
        chars += string.ascii_uppercase
    if no_lower is False:
        chars += string.ascii_lowercase
    if no_digit is False:
        chars += string.digits
    if not chars:
        raise Exception('chars is empty! change function args!')
    return ''.join([rand.choice(chars) for _ in range(n)])


def success_message(message, request):
    return messages.success(request, mark_safe(message))


def error_message(message, request):
    return messages.error(request, mark_safe(message), extra_tags='danger')


def info_message(message, request):
    return messages.info(request, mark_safe(message))


def warning_message(message, request):
    return messages.warning(request, mark_safe(message))

TAG_LEVEL = 100


def add_tag_message(message, tag, request):
    return messages.add_message(request, TAG_LEVEL, message, extra_tags=tag)


def get_tag_messages(tag, request):
    return [m.message for m in messages.get_messages(request)
            if (tag in m.tags) and m.level == TAG_LEVEL]


def send_form_errors(form, request):
    msgs = []
    for k, v in form.errors.items():
        msg = '' if k.startswith('__') else '{0}: '.format(k)
        msgs.append('<li>{0}{1}</li>'.format(msg, ', '.join(v)))

    if msgs:
        return error_message(''.join(msgs), request)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_aware_datetime(date_str):
    ret = parse_datetime(date_str)
    if not is_aware(ret):
        ret = make_aware(ret)
    return ret


def get_current_page_size(request, default=None):
    default = default or settings.PAGINATION_DEFAULT_PAGINATION
    page_size = default
    try:
        page_size = int(request.GET.get('page_size'))
    except:
        pass

    if page_size <= 0:
        page_size = default

    return min(page_size, settings.PAGINATION_MAX_PAGE_SIZE)


def send_sms(message, to, from_=None):
    from_ = from_ or settings.TWILIO_DEFAULT_CALLERID
    if settings.SMS_MOCK_SENDING:
        print("Sending sms from {} to {}: {}".format(from_, to, message))
        return
    twilio_client = get_twilio_client()
    return twilio_client.messages.create(to=to, from_=from_,
                                         body=message)


def ex_reverse(viewname, **kwargs):
    if viewname.startswith('http://') or viewname.startswith('https://'):
        return viewname

    host = kwargs.pop('hostname', None)
    request = kwargs.pop('request', None)
    scheme = kwargs.pop('scheme', None)
    if not host:
        host = request.get_host() if request else settings.HOSTNAME

    if not viewname:
        rel_path = ''
    elif viewname.startswith('/'):
        rel_path = viewname
    else:
        rel_path = reverse(viewname, **kwargs)

    scheme = '{}://'.format(scheme) if scheme else ''

    return '{0}{1}{2}'.format(scheme, host, rel_path)


class NotFoundView(object):
    @classmethod
    def as_view(cls):
        return cls.handler

    @classmethod
    def handler(cls, request):
        raise Http404


class PermissionRequiredMixin(DjangoPermissionRequiredMixin):

    def get_permission_required(self):
        perms = self.permission_required or ()
        if isinstance(perms, dict):
            perms = perms.get(self.request.method.lower(), ()) or ()

        if isinstance(perms, six.string_types):
            perms = (perms, )

        return perms

    def handle_no_authenticated(self):
        if self.request.is_ajax():
            return JsonResponse({'error': 'Not Authorized'}, status=401)
        return redirect_to_login(self.request.get_full_path(),
                                 self.get_login_url(),
                                 self.get_redirect_field_name())

    def handle_no_permission(self):
        if self.request.is_ajax():
            return JsonResponse({'error': 'Permission Denied'}, status=403)
        if self.raise_exception:
            raise PermissionDenied(self.get_permission_denied_message())
        return render(self.request, "network_monitor/no-permission.html", status=403)

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated():
            return self.handle_no_authenticated()
        if not self.has_permission():
            return self.handle_no_permission()
        return super(PermissionRequiredMixin, self
                     ).dispatch(request, *args, **kwargs)


def to_dict(obj, fields=None, fields_map={}, extra_fields=None):
    '''
    convert a model object to a python dict.
    @param fields: list of fields which we want to show in return value.
        if fields=None, we show all fields of model object
    @type fields: list
    @param fields_map: a map converter to show fields as a favorite.
        every field can bind to a lambda function in fields_map.
        if a field was bind to a None value in fields_map, we ignore this field
        to show in result
    @type fields_map: dict
    '''
    data = {}

    if fields is None:
        fields = [f.name for f in obj.__class__._meta.fields]
    fields.extend(extra_fields or [])
    for field in fields:
        if field in fields_map:
            if fields_map[field] is None:
                continue
            v = fields_map.get(field)()
        else:
            v = getattr(obj, field, None)
        if isinstance(v, datetime.datetime):
            data[field] = v.isoformat() + 'Z'
        elif isinstance(v, datetime.date):
            data[field] = v.isoformat()
        elif isinstance(v, decimal.Decimal):
            data[field] = float(v)
        else:
            data[field] = v

    return data


class SafeFormat(object):
    def __init__(self, **kw):
        self.__dict = kw

    def __getitem__(self, name):
        return self.__dict.get(name, '{%s}' % name)


MAC_RE = r'^([0-9a-fA-F]{2}([:-]?|$)){6}$'
mac_re = re.compile(MAC_RE)

class MACAddressFormField(fields.RegexField):
    default_error_messages = {
        'invalid': _(u'Enter a valid MAC address.'),
    }

    def __init__(self, *args, **kwargs):
        super(MACAddressFormField, self).__init__(mac_re, *args, **kwargs)


class MACAddressField(models.Field):
    empty_strings_allowed = False
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 17
        super(MACAddressField, self).__init__(*args, **kwargs)

    def get_internal_type(self):
        return "CharField"

    def get_prep_value(self, value):
        value = super(MACAddressField, self).get_prep_value(value)
        if isinstance(value, six.string_types):
            value = value.lower()
        return value

    def formfield(self, **kwargs):
        defaults = {'form_class': MACAddressFormField}
        defaults.update(kwargs)
        return super(MACAddressField, self).formfield(**defaults)


if six.PY2:
    class CompletedProcess(object):
        """A process that has finished running.

        This is returned by run().

        Attributes:
          args: The list or str args passed to run().
          returncode: The exit code of the process, negative for signals.
          stdout: The standard output (None if not captured).
          stderr: The standard error (None if not captured).
        """

        def __init__(self, args, returncode, stdout=None, stderr=None):
            self.args = args
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

        def __repr__(self):
            args = ['args={!r}'.format(self.args),
                    'returncode={!r}'.format(self.returncode)]
            if self.stdout is not None:
                args.append('stdout={!r}'.format(self.stdout))
            if self.stderr is not None:
                args.append('stderr={!r}'.format(self.stderr))
            return "{}({})".format(type(self).__name__, ', '.join(args))

        def check_returncode(self):
            """Raise CalledProcessError if the exit code is non-zero."""
            if self.returncode:
                raise subprocess.CalledProcessError(self.returncode, self.args, self.stdout,
                                         self.stderr)


    def py2_subprocess_run(popenargs, input=None, timeout=None, check=False, **kwargs):
        if not isinstance(popenargs, (tuple, list)):
            popenargs = (popenargs,)
        if input is not None:
            if 'stdin' in kwargs:
                raise ValueError('stdin and input arguments may not both be used.')
            kwargs['stdin'] = subprocess.PIPE

        process = subprocess.Popen(*popenargs, **kwargs)
        stdout, stderr = process.communicate(input)
        retcode = process.poll()
        if check and retcode:
            raise subprocess.CalledProcessError(retcode, process.args,
                                     output=stdout, stderr=stderr)
        return CompletedProcess(popenargs, retcode, stdout, stderr)


def scan_network_ips(ip_range):
    nm = nmap.PortScanner()
    scans = nm.scan(hosts=ip_range, arguments='-sn')
    res = {}
    for ip, data in scans.get('scan', {}).items():
        mac = arpreq.arpreq(ip)
        data.setdefault('vendor', {}).setdefault('mac', mac)
        res[ip] = data
    return res


def find_mac_manufacture(mac, abort=False):
    url = '{}/{}'.format(settings.MACVENDORS_API_URL.rstrip('/'), mac)
    try:
        res = requests.get(url, timeout=settings.MACVENDORS_API_TIMEOUT)
    except Exception:
        res = None

    if not res or not res.ok:
        if abort:
            msg = 'Not Found' if res else 'Timeout Error'
            raise Exception(msg)
        return None
    return res.text
