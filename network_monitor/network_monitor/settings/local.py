from .base import *

SECRET_KEY = '!!!local_secret_key!!!'
HOSTNAME = 'localhost:8000'
DEBUG = True
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'network_monitor',
        'HOST': 'localhost',
        'PORT': '5432',
        'USER': 'postgres',
        'PASSWORD': 'a',
    }
}

EMAIL_MOCK_SENDING = True
SMS_MOCK_SENDING = True
INSTALLED_FEATURES = ['network_monitor.features.ping.apps.PingConfig', 'network_monitor.features.nmap.apps.NmapConfig']
INSTALLED_APPS.extend(INSTALLED_FEATURES)
