import os
import datetime
import decimal

from django.utils import six
from pytimeparse.timeparse import timeparse
try:
    from configparser import ConfigParser, _UNSET
except ImportError:
    from ConfigParser import SafeConfigParser as ConfigParser, NoOptionError

from .base import BASE_DIR, CUSTOM_CONFIG_INI_PATH, DATABASES

LOCAL_CONF_PATH = os.path.join(BASE_DIR, 'network_monitor', 'settings', 'custom_config.ini')
GLOBAL_CONF_PATH = os.getenv('NETWORK_MONITOR_CONFIG_INI', '') or CUSTOM_CONFIG_INI_PATH

if six.PY2:
    class NoDefault:
        pass


    class ExConfigParser(ConfigParser):
        def getboolean(self, section, option, default=NoDefault):
            v = self.get(section, option, default=default)
            if v == default:
                return v
            if v.lower() not in self._boolean_states:
                raise ValueError('Not a boolean: %s' % v)
            return self._boolean_states[v.lower()]

        def getint(self, section, option, default=NoDefault):
            return self._get(section, int, option, default=default)

        def getfloat(self, section, option, default=NoDefault):
            return self._get(section, float, option, default=default)

        def getdecimal(self, section, option, default=NoDefault):
            return self._get(section, decimal.Decimal, option, default=default)

        def getlist(self, section, option, default=NoDefault):
            v = self.get(section, option, default=default)
            if v == default:
                return v
            v = v or ''
            return [i.strip() for i in v.split(',') if i.strip()]

        def getduration(self, section, option, default=NoDefault, as_delta=False):
            v = self.get(section, option, default=default)
            if v == default:
                return v
            if v and v.isdigit():
                v = v + 's'

            seconds = timeparse(v)
            if as_delta:
                return datetime.timedelta(seconds=seconds)
            return seconds

        def _get(self, section, conv, option, default=NoDefault):
            return conv(self.get(section, option, default=default))

        def get(self, section, option, raw=False, vars=None, default=NoDefault):
            try:
                v = ConfigParser.get(self, section, option, raw, vars)
            except NoOptionError:
                if default != NoDefault:
                    return default
                raise
            return v

        def options_dict(self, section):
            return {opt: self.get(section, opt) for opt in self.options(section)}

else:
    six.exec_("""
class ExConfigParser(ConfigParser):
    ''' Extended ConfigParser '''

    @staticmethod
    def _getlistconv(v):
        v = v or ''
        return [i.strip() for i in v.split(',') if i.strip()]

    @staticmethod
    def _getdurationconv(v, as_delta=True):

        if v and v.isdigit():
            v = v + 's'

        seconds = timeparse(v)
        if as_delta:
            return datetime.timedelta(seconds=seconds)
        return seconds

    def _get(self, section, conv, option, **kwargs):
        conv_args = conv_kwargs = None
        if 'conv_args' in kwargs:
            conv_args = kwargs.pop('conv_args')
        if 'conv_kwargs' in kwargs:
            conv_kwargs = kwargs.pop('conv_kwargs')
        return conv(self.get(section, option, **kwargs), *(conv_args or ()), **(conv_kwargs or {}))

    def getdecimal(self, section, option, *, raw=False, vars=None, fallback=_UNSET, **kwargs):
        return self._get_conv(section, option, decimal.Decimal, raw=raw, vars=vars, fallback=fallback, **kwargs)

    def getlist(self, section, option, *, raw=False, vars=None, fallback=_UNSET, **kwargs):
        return self._get_conv(section, option, self._getlistconv, raw=raw, vars=vars, fallback=fallback, **kwargs)

    def getduration(self, section, option, *, raw=False, vars=None, fallback=_UNSET, **kwargs):
        kwargs['conv_kwargs'] = {'as_delta': kwargs.pop('as_delta', True)}
        return self._get_conv(section, option, self._getdurationconv, raw=raw, vars=vars, fallback=fallback, **kwargs)

    def options_dict(self, section):
        return {opt: self.get(section, opt) for opt in self.options(section)}
""")

config = ExConfigParser()
config.read([LOCAL_CONF_PATH, GLOBAL_CONF_PATH])

############## Load custom settings from ini #################
if config.has_option('cfg', 'SECRET_KEY'):
    SECRET_KEY = config.get('cfg', 'SECRET_KEY')

# email setting
if config.has_option('cfg', 'EMAIL_BACKEND'):
    EMAIL_BACKEND = config.get('cfg', 'EMAIL_BACKEND')
if config.has_option('cfg', 'MAILGUN_SERVER_NAME'):
    MAILGUN_SERVER_NAME = config.get('cfg', 'MAILGUN_SERVER_NAME')
if config.has_option('cfg', 'MAILGUN_ACCESS_KEY'):
    MAILGUN_ACCESS_KEY = config.get('cfg', 'MAILGUN_ACCESS_KEY')

# twilio sms setting
if config.has_option('cfg', 'TWILIO_ACCOUNT_SID'):
    TWILIO_ACCOUNT_SID = config.get('cfg', 'TWILIO_ACCOUNT_SID')
if config.has_option('cfg', 'TWILIO_AUTH_TOKEN'):
    TWILIO_AUTH_TOKEN = config.get('cfg', 'TWILIO_AUTH_TOKEN')
if config.has_option('cfg', 'TWILIO_DEFAULT_CALLERID'):
    TWILIO_DEFAULT_CALLERID = config.get('cfg', 'TWILIO_DEFAULT_CALLERID')

# Google social auth2 setting
if config.has_option('cfg', 'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY'):
    SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = config.get('cfg', 'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY')
if config.has_option('cfg', 'SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET'):
    SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = config.get('cfg', 'SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET')

if config.has_option('cfg', 'HOSTNAME'):
    HOSTNAME = config.get('cfg', 'HOSTNAME')
if config.has_option('cfg', 'DEBUG'):
    DEBUG = config.getboolean('cfg', 'DEBUG')
if config.has_option('cfg', 'ALLOWED_HOSTS'):
    ALLOWED_HOSTS = config.getlist('cfg', 'ALLOWED_HOSTS')
if config.has_option('cfg', 'INSTALLED_FEATURES'):
    INSTALLED_FEATURES = config.getlist('cfg', 'INSTALLED_FEATURES')
if config.has_option('cfg', 'DB_ENGINE'):
    DATABASES['default']['ENGINE'] = config.get('cfg', 'DB_ENGINE')
if config.has_option('cfg', 'DB_NAME'):
    DATABASES['default']['NAME'] = config.get('cfg', 'DB_NAME')
if config.has_option('cfg', 'DB_HOST'):
    DATABASES['default']['HOST'] = config.get('cfg', 'DB_HOST')
if config.has_option('cfg', 'DB_PORT'):
    DATABASES['default']['PORT'] = config.getint('cfg', 'DB_PORT')
if config.has_option('cfg', 'DB_USER'):
    DATABASES['default']['USER'] = config.get('cfg', 'DB_USER')
if config.has_option('cfg', 'DB_PASSWORD'):
    DATABASES['default']['PASSWORD'] = config.get('cfg', 'DB_PASSWORD')
if config.has_option('cfg', 'BOOTSTRAP_ADMIN_SIDEBAR_MENU'):
    BOOTSTRAP_ADMIN_SIDEBAR_MENU = config.getboolean('cfg', 'BOOTSTRAP_ADMIN_SIDEBAR_MENU')
if config.has_option('cfg', 'LANGUAGE_CODE'):
    LANGUAGE_CODE = config.get('cfg', 'LANGUAGE_CODE')
if config.has_option('cfg', 'TIME_ZONE'):
    TIME_ZONE = config.get('cfg', 'TIME_ZONE')
if config.has_option('cfg', 'USE_I18N'):
    USE_I18N = config.getboolean('cfg', 'USE_I18N')
if config.has_option('cfg', 'USE_L10N'):
    USE_L10N = config.getboolean('cfg', 'USE_L10N')
if config.has_option('cfg', 'USE_TZ'):
    USE_TZ = config.getboolean('cfg', 'USE_TZ')
if config.has_option('cfg', 'PAGINATION_DEFAULT_PAGINATION'):
    PAGINATION_DEFAULT_PAGINATION = config.getint('cfg', 'PAGINATION_DEFAULT_PAGINATION')
if config.has_option('cfg', 'PAGINATION_MAX_PAGE_SIZE'):
    PAGINATION_MAX_PAGE_SIZE = config.getint('cfg', 'PAGINATION_MAX_PAGE_SIZE')
if config.has_option('cfg', 'BROKER_URL'):
    BROKER_URL = config.get('cfg', 'BROKER_URL')
if config.has_option('cfg', 'CELERY_RESULT_BACKEND'):
    CELERY_RESULT_BACKEND = config.get('cfg', 'CELERY_RESULT_BACKEND')
if config.has_option('cfg', 'EMAIL_MOCK_SENDING'):
    EMAIL_MOCK_SENDING = config.getboolean('cfg', 'EMAIL_MOCK_SENDING')
if config.has_option('cfg', 'SMS_MOCK_SENDING'):
    SMS_MOCK_SENDING = config.getboolean('cfg', 'SMS_MOCK_SENDING')
if config.has_option('cfg', 'DEFAULT_EMAIL_FROM'):
    DEFAULT_EMAIL_FROM = config.get('cfg', 'DEFAULT_EMAIL_FROM')
if config.has_option('cfg', 'MON_SERVICE_INTERVAL'):
    MON_SERVICE_INTERVAL = config.getint('cfg', 'MON_SERVICE_INTERVAL')
if config.has_option('cfg', 'REDIS_MEM_HOST'):
    REDIS_MEM_HOST = config.get('cfg', 'REDIS_MEM_HOST')
if config.has_option('cfg', 'REDIS_MEM_PORT'):
    REDIS_MEM_PORT = config.getint('cfg', 'REDIS_MEM_PORT')
if config.has_option('cfg', 'REDIS_MEM_DB'):
    REDIS_MEM_DB = config.getint('cfg', 'REDIS_MEM_DB')
if config.has_option('cfg', 'REDIS_MEM_PREFIX'):
    REDIS_MEM_PREFIX = config.get('cfg', 'REDIS_MEM_PREFIX')
if config.has_option('cfg', 'REDIS_MEM_DEFAULT_EXPIRE'):
    REDIS_MEM_DEFAULT_EXPIRE = config.getint('cfg', 'REDIS_MEM_DEFAULT_EXPIRE')
if config.has_option('cfg', 'MACVENDORS_API_URL'):
    MACVENDORS_API_URL = config.get('cfg', 'MACVENDORS_API_URL')
if config.has_option('cfg', 'MACVENDORS_API_TIMEOUT'):
    MACVENDORS_API_TIMEOUT = config.getint('cfg', 'MACVENDORS_API_TIMEOUT')
if config.has_option('cfg', 'ENABLE_REGISTER_USER_VIEW'):
    ENABLE_REGISTER_USER_VIEW = config.getboolean('cfg', 'ENABLE_REGISTER_USER_VIEW')
