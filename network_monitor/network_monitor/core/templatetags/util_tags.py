import json as JSON
from datetime import timedelta
from django import template
from django.apps import apps
from django.conf import settings
from django.utils import six

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode
from collections import OrderedDict
from django.contrib.humanize.templatetags.humanize import naturaltime
from django.core.urlresolvers import reverse
from django.utils.safestring import mark_safe
from network_monitor.helpers.utils import get_aware_datetime


register = template.Library()


@register.simple_tag(takes_context=True)
def active_if(context, *view_name):
    if context.request.resolver_match.view_name in view_name:
        return 'active'
    return ''


@register.filter(name='addcss')
def addcss(field, css):
    return field.as_widget(attrs={"class": css})


@register.filter
def join_and(value):
    """Given a list of strings, format them with commas and spaces, but
    with 'and' at the end.

    >>> join_and(['apples', 'oranges', 'pears'])
    "apples, oranges, and pears"

    """
    # convert numbers to strings
    value = [str(item) for item in value]
    if len(value) == 0:
        return ''
    if len(value) == 1:
        return value[0]

    # join all but the last element
    all_but_last = ", ".join(value[:-1])
    return "%s, and %s" % (all_but_last, value[-1])


@register.simple_tag
def tags_span(tags, cls='default', NA='-'):
    tags = tags or []
    tags_html = []
    if isinstance(tags, six.string_types):
        tags = tags.split(',')
    for tag in tags:
        tag = str(tag).strip()
        if not tag:
            continue
        tags_html.append(
            '<span class="label label-{cls}">{tag}</span>'.format(
                tag=tag, cls=cls))
    html = ' '.join(tags_html)
    return mark_safe(html or NA)


@register.simple_tag(takes_context=True)
def sorting_link(context, text, value, field='order_by', direction=''):
    dict_ = context.request.GET.copy()
    icon = 'fa fa-fw '
    link_css = ''
    if field in dict_.keys():
        if dict_[field].startswith('-') and dict_[field].lstrip('-') == value:
            dict_[field] = value
            icon += 'fa-sort-desc'
            link_css += 'text-italic'
        elif dict_[field].lstrip('-') == value:
            dict_[field] = "-" + value
            icon += 'fa-sort-asc'
            link_css += 'text-italic'
        else:
            dict_[field] = direction + value
            icon += 'fa-sort gray2-color'
    else:
        dict_[field] = direction + value
        icon += 'fa-sort gray2-color'
    url = urlencode(OrderedDict(sorted(dict(dict_).items())), True)

    return mark_safe('<a href="?{0}" class="table-sorting {1}">{2}<i class="{3}">'
                     '</i></a>'.format(url, link_css, text, icon))


@register.simple_tag(takes_context=True)
def ex_url(context, name, *args, **kwargs):
    ''' External url tag '''
    hostname = context.get('hostname') or kwargs.pop('_hostname', None)
    if not hostname:
        request = context.get('request')
        hostname = request and request.get_host()
    if not hostname:
        hostname = settings.HOSTNAME

    if not name:
        return hostname
    url = reverse(name, args=args, kwargs=kwargs)
    return '{0}{1}'.format(hostname, url)


def _get_field(Model, field_name):
    if isinstance(Model, six.string_types):
        Model = apps.get_model(Model)

    return Model._meta.get_field(field_name)


@register.simple_tag
def get_verbose_field_name(Model, field_name):
    """
    Returns verbose_name for a field.
    """
    field = _get_field(Model, field_name)
    return field.verbose_name


@register.simple_tag(takes_context=True)
def page_size_combo(context, *sizes, **kwargs):
    if not sizes:
        sizes = (10, 20, 30, 50, 100, 150, 200)
    default = kwargs.get('default') or settings.PAGINATION_DEFAULT_PAGINATION
    page_size = context.request.GET.get('page_size') or default
    html = 'Page Size <select class="page-size" name="page_size">'
    for size in sizes:
        selected = ('selected' if str(size) == str(page_size) else '')
        html += '<option value="{0}" {1}>{0}</option>'.format(
            size, selected)
    html += '</select>'
    return mark_safe(html)

@register.simple_tag(takes_context=True)
def pagination_info(context, *sizes, **kwargs):
    paginator = context.get('paginator')
    page_obj = context.get('page_obj')

    html = '<span class="pagination-info">Displaying <span class="pagination-info-start">{start_index}</span> - <span '\
    'class="pagination-info-end">{end_index}</span> of <span class="pagination-info-count">{records_count}</span> ' \
    'records</span>'.format(start_index=page_obj.start_index(), end_index=page_obj.end_index(),
                            records_count=paginator.count)
    return mark_safe(html)

@register.filter
def iso_dt(s):
    if not s:
        return None
    return get_aware_datetime(s)


@register.filter(name='device_status_tag')
def device_status_tag(device):
    from network_monitor.core.models import Device
    value = device.status
    label = device.status_display
    status_classes = {
        Device.STATUS_UP: 'success',
        Device.STATUS_DOWN: 'danger',
    }
    cls = status_classes.get(value, 'muted')
    if value == Device.STATUS_UP:
        label = '{}({})'.format(label, naturaltime(device.last_seen).replace(u'\xa0', u' '))
    elif value == Device.STATUS_DOWN:
        if device.last_seen:
            label = '{}({})'.format(label, naturaltime(device.last_seen).replace(u'\xa0', u' '))
        else:
            label = 'Never Seen'
            cls = 'muted'
    html = '<span class="fa fa-circle text-{0}"></span> <span class="text-{0}">{1}</span>'.format(
        cls, label)
    return mark_safe(html)


@register.filter(name='seconds_humanize')
def seconds_humanize(s):
    value = ''
    m = h = 0
    if s >= 3600:
        h = s // 3600
        s = s % 3600
        value = '{} hour{}'.format(h, 's' if h > 1 else '')
    if s >= 60:
        m = s // 60
        s = s % 60
        value = '{}{} minute{}'.format(value + ' ' if value else '', m,
                                       's' if m > 1 else '')
    if s > 0:
        value = '{}{} second{}'.format(value + ' ' if value else '', s,
                                       's' if s > 1 else '')
    return value


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)


@register.filter
def split(s, splitter=" "):
    return s.split(splitter)


@register.filter
def active_icon(value):
    cls = "fa "
    if value:
        cls += 'fa-check text-success'
    else:
        cls += 'fa-close text-danger'
    return mark_safe('<span class="{}"><span>'.format(cls))


@register.filter
def severity_tag(severity):
    from network_monitor.core import models
    severities = dict(models.SEVERITY_CHOICES)
    label = severities.get(severity) or 'Info'

    html = '<span class="label severity_{}-label">{}</span>'.format(
        label.lower(), label
    )
    return mark_safe(html)


@register.filter
def json(a):
    json_str = JSON.dumps(a)
    escapes = ['<', '>', '&']
    for c in escapes:
        json_str = json_str.replace(c, r'\u%04x' % ord(c))

    return mark_safe(json_str)
json.is_safe = True


@register.simple_tag()
def add_date(date, **kwargs):
    args = {}
    for a in ['seconds', 'minutes', 'hours', 'days']:
        v = kwargs.get(a)
        if v:
            args[a] = v
    if args:
        date = date + timedelta(**args)
    return date
