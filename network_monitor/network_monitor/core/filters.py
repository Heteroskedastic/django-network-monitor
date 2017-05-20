from django import forms
from distutils.util import strtobool
from django_filters import FilterSet, filters, OrderingFilter

from .models import Device, Event, DeviceFeature, Threshold, SEVERITY_CHOICES


class CustomDeviceOrderingFilter(OrderingFilter):

    def __init__(self, *args, **kwargs):
        super(CustomDeviceOrderingFilter, self).__init__(*args, **kwargs)
        self.extra['choices'] += [
            ('status', 'Status'),
            ('-status', 'Status (descending)'),
        ]


    def filter(self, qs, value):
        if any(v in ['status', '-status'] for v in value):
            return qs.order_by(*(value+['-last_seen']))

        return super(CustomDeviceOrderingFilter, self).filter(qs, value)


class DevicesFilter(FilterSet):
    STATUS_NEVER_SEEN = 'never_seen'

    active = filters.TypedChoiceFilter(
        choices=[(None, ''), ('true', 'Active Only'),
                 ('false', 'Inactive Only')],
        coerce=strtobool,
        widget=forms.Select(attrs={
            'style': 'width: 150px',
            'data-placeholder': 'Filter by Active',
            'class': 'chosen-select-deselect'}))
    status = filters.TypedChoiceFilter(
        method='status_filter', required=False,
        choices=((None, ''), )+Device.STATUS_CHOICES+((STATUS_NEVER_SEEN, 'Never Seen'), ),
        widget=forms.Select(attrs={
            'style': 'width: 150px',
            'data-placeholder': 'Filter by Status',
            'class': 'chosen-select'}))
    tags = filters.CharFilter(lookup_expr='icontains', required=False, widget=forms.TextInput(attrs={
        'placeholder': 'Filter by Tags', 'class': 'form-control', 'style': 'height: 28px',
    }))
    name = filters.CharFilter(lookup_expr='icontains', required=False, widget=forms.TextInput(attrs={
        'placeholder': 'Filter by Name', 'class': 'form-control', 'style': 'height: 28px',
    }))
    address = filters.CharFilter(lookup_expr='icontains', required=False, widget=forms.TextInput(attrs={
        'placeholder': 'Filter by Address', 'class': 'form-control', 'style': 'height: 28px',
    }))
    feature = filters.MultipleChoiceFilter(
        method='feature_filter', required=False, choices=DeviceFeature.FEATURE_CHOICES,
        widget=forms.SelectMultiple(attrs={
            'style': 'width: 200px',
            'data-placeholder': 'Filter by Feature',
            'class': 'chosen-select'}))

    order_by = CustomDeviceOrderingFilter(
        fields=['id', 'name', 'address', 'mac', 'status', 'active', 'username', 'password', 'tags']
    )

    def status_filter(self, queryset, name, value):
        if value == self.STATUS_NEVER_SEEN:
            return queryset.filter(status=Device.STATUS_DOWN, last_seen=None)
        elif value == Device.STATUS_DOWN:
            return queryset.filter(status=Device.STATUS_DOWN).exclude(last_seen=None)
        return queryset.filter(status=value)

    def feature_filter(self, queryset, name, value):
        return queryset.filter(**{'feature__feature__in': value, 'feature__active': True}).distinct()

    class Meta:
        model = Device
        fields = ['status', 'active', 'feature', 'tags', 'name', 'address']


class EventsFilter(FilterSet):

    severity = filters.MultipleChoiceFilter(
        required=False, choices=SEVERITY_CHOICES,
        widget=forms.SelectMultiple(attrs={
            'style': 'width: 250px',
            'data-placeholder': 'Filter by Severity',
            'class': 'chosen-select'}))

    feature = filters.TypedChoiceFilter(
        choices=((None, ''), ) + DeviceFeature.FEATURE_CHOICES,
        widget=forms.Select(attrs={
            'style': 'width: 150px',
            'data-placeholder': 'Filter by Feature',
            'class': 'chosen-select-deselect'}))

    device = filters.ModelChoiceFilter(
        empty_label='', required=False, queryset=Device.objects.all(),
        widget=forms.Select(attrs={
            'style': 'width: 150px',
            'data-placeholder': 'Filter by Device',
            'class': 'chosen-select-deselect'}))

    threshold = filters.ModelChoiceFilter(
        empty_label='', required=False, queryset=Threshold.objects.all(),
        widget=forms.Select(attrs={
            'style': 'width: 250px',
            'data-placeholder': 'Filter by Threshold',
            'class': 'chosen-select-deselect'}))

    order_by = OrderingFilter(
        fields=['id', 'device', 'feature', 'threshold', 'severity', 'summary', 'first_time', 'last_time', 'count',
                'clear_time', 'notify_time']
    )

    class Meta:
        model = Event
        fields = ['feature', 'device', 'threshold', 'severity', ]
