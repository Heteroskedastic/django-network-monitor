from django.core.validators import ip_address_validators
from django.forms import ValidationError, CheckboxInput, TextInput
from dynamic_preferences.preferences import Section
from dynamic_preferences.types import BooleanPreference, StringPreference, IntegerPreference, StringSerializer
from dynamic_preferences.registries import global_preferences_registry

# we create some section objects to link related preferences together
from network_monitor.core.forms import boolean_toggle_attrs

dhcp_scan = Section('dhcp_scan')


@global_preferences_registry.register
class DhcpScanIsEnabled(BooleanPreference):
    field_kwargs = {
        'required': False,
        'help_text': 'Enable/Disable DHCP scanning',
        'widget': CheckboxInput(attrs=boolean_toggle_attrs)
    }
    section = dhcp_scan
    name = 'is_enabled'
    verbose_name = ''
    default = True


# We start with a global preference
@global_preferences_registry.register
class DhcpScanIpRanges(StringPreference):
    field_kwargs = {
        'required': False,
        'help_text': 'List of ip ranges to be scanned in dhcp. i.e: 192.168.1.1-255 OR 192.168.1.0/24 OR 192.168.1.100',
        'widget': TextInput(attrs={'data-role': 'tagsinput', 'width': '100%'})
    }
    section = dhcp_scan
    verbose_name = 'IP Ranges'
    name = 'ip_ranges'
    default = ''

    @classmethod
    def clean_ip_range(cls, ip_range):
        ip_validator = ip_address_validators('both', False)[0][0]
        if '/' in ip_range:
            ip, r = ip_range.split('/', 1)
            ip_validator(ip)
            if not r.isdigit() or int(r) < 1 or int(r) > 32:
                raise ValidationError('Invalid ip range. {} should be between 1 and 32'.format(r))
        elif '-' in ip_range:
            ip, r = ip_range.split('-', 1)
            ip_validator(ip)
            if not r.isdigit() or int(r) < 0 or int(r) > 255:
                raise ValidationError('Invalid ip range. {} should be between 0 and 255'.format(r))
        else:
            ip_validator(ip_range)
        return ip_range

    def validate(self, value):
        # ensure the meaning of life is always 42
        if not value:
            return
        for ip_range in value.split(','):
            ip_range = ip_range.strip()
            self.clean_ip_range(ip_range)


@global_preferences_registry.register
class DhcpScanAutoAddNewDeviceEnabled(BooleanPreference):
    field_kwargs = {
        'required': False,
        'help_text': 'Automatically add new found devices in dhcp scanning.'
    }
    section = dhcp_scan
    name = 'auto_add_new'
    verbose_name = 'Auto add new found devices?'
    default = True


@global_preferences_registry.register
class DhcpScanAutoDisablNotSeenDevicesAfterMonthEnabled(IntegerPreference):
    field_kwargs = {
        'required': True,
        'help_text': 'Automatically disable/archive devices not seen in X days in dhcp scanning. (leave "0" to ignore)'
    }
    section = dhcp_scan
    name = 'auto_disable_after'
    verbose_name = 'Number of days to inactive device if not seen'
    default = 0
