SECRET_KEY = '<SECRET_KEY>'
MAILGUN_SERVER_NAME = '<MAILGUN_SERVER_NAME>'
MAILGUN_ACCESS_KEY = '<MAILGUN_ACCESS_KEY>'
TWILIO_ACCOUNT_SID = '<TWILIO_ACCOUNT_SID>'
TWILIO_AUTH_TOKEN = '<TWILIO_AUTH_TOKEN>'
TWILIO_DEFAULT_CALLERID = '<TWILIO_DEFAULT_CALLERID>'
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '<SOCIAL_AUTH_GOOGLE_OAUTH2_KEY>'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = '<SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET>'
HOSTNAME = 'localhost:8000'
DEBUG = False
ALLOWED_HOSTS = ['*']
ADMINS = [('admin1', 'admin1@gmail.com'), ('admin2', 'admin2@gmail.com')]
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
# INSTALLED_FEATURES = ['network_monitor.features.ping.apps.PingConfig', 'network_monitor.features.nmap.apps.NmapConfig']
# BOOTSTRAP_ADMIN_SIDEBAR_MENU = True
# LANGUAGE_CODE = 'en-us'
# TIME_ZONE = 'UTC'
# USE_I18N = True
# USE_L10N = True
# USE_TZ = True
# PAGINATION_DEFAULT_PAGINATION = 30
# PAGINATION_MAX_PAGE_SIZE = 200
# BROKER_URL = 'redis://localhost:6379/3'
# CELERY_RESULT_BACKEND = 'redis://localhost:6379/3'
# EMAIL_MOCK_SENDING = False
# SMS_MOCK_SENDING = False
# ENABLE_REGISTER_USER_VIEW = False
# DEFAULT_EMAIL_FROM = 'info@networkmonitor.io'
# MON_SERVICE_INTERVAL = 20
# REDIS_MEM_HOST = 'localhost'
# REDIS_MEM_PORT = 6379
# REDIS_MEM_DB = 1
# REDIS_MEM_PREFIX = 'network-monitor:'
# REDIS_MEM_DEFAULT_EXPIRE = '600'
# MACVENDORS_API_URL = 'http://api.macvendors.com/'
# MACVENDORS_API_TIMEOUT = 5
