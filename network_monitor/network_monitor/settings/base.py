"""
Django settings for network_monitor project.

Generated by 'django-admin startproject' using Django 1.9.9.

For more information on this file, see
https://docs.djangoproject.com/en/1.9/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.9/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
from kombu import Exchange
from kombu import Queue

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EXTERNAL_CONFIG_PATH = '/opt/webapps/network_monitor/etc/external_config.py'

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.9/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '<SECRET_KEY>'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['*']

# Application definition

# all monitoing features app should be included here.
INSTALLED_FEATURES = [
    'network_monitor.features.ping.apps.PingConfig', 'network_monitor.features.nmap.apps.NmapConfig',
]

INSTALLED_APPS = [
    'bootstrap_admin',  # always before django.contrib.admin
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'kombu.transport.django',
    'djcelery',
    'bootstrap3',
    'social.apps.django_app.default',
    'django_filters',
    'pagination_bootstrap',
    'phonenumber_field',
    'dbbackup',
    'ckeditor',
    'network_monitor.core',
]

MIDDLEWARE_CLASSES = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'pagination_bootstrap.middleware.PaginationMiddleware',
]

ROOT_URLCONF = 'network_monitor.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'network_monitor', 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'social.apps.django_app.context_processors.backends',
                'social.apps.django_app.context_processors.login_redirect',
            ],
        },
    },
]

AUTHENTICATION_BACKENDS = (
    'social.backends.google.GoogleOAuth2',
    'django.contrib.auth.backends.ModelBackend',
)


WSGI_APPLICATION = 'network_monitor.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.9/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/1.9/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

BOOTSTRAP_ADMIN_SIDEBAR_MENU = True

# Internationalization
# https://docs.djangoproject.com/en/1.9/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.9/howto/static-files/

STATIC_URL = '/static/'

STATIC_ROOT = os.path.join(BASE_DIR, "collected_static")

STATICFILES_DIRS = (
    os.path.join(BASE_DIR, "static"),
)

MEDIA_URL = '/media/'

MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# pagination setting
PAGINATION_DEFAULT_PAGINATION = 30
PAGINATION_MAX_PAGE_SIZE = 200

# email setting
EMAIL_BACKEND = 'django_mailgun.MailgunBackend'
MAILGUN_SERVER_NAME = '<SERVER_NAME>'
MAILGUN_ACCESS_KEY = '<MAILGUN_ACCESS_KEY>'

# twilio sms setting
TWILIO_ACCOUNT_SID = '<ACCOUNT_SID>'
TWILIO_AUTH_TOKEN = '<AUTH_TOKEN>'
TWILIO_DEFAULT_CALLERID = '<DEFAULT_CALLERID>'

# celery specific settings
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERYBEAT_SCHEDULER = 'djcelery.schedulers.DatabaseScheduler'
# CELERY_RESULT_BACKEND = 'djcelery.backends.database:DatabaseBackend'
# BROKER_URL = 'django://'
# if you want to use redis as a celery backend
BROKER_URL = 'redis://localhost:6379/3'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/3'
CELERY_QUEUES = (
    Queue('default', Exchange('default'), routing_key='default'),
    Queue('periodic_tasks', Exchange('periodic_tasks'), routing_key='periodic_tasks'),
    Queue('periodic_tasks_long', Exchange('periodic_tasks_long'), routing_key='periodic_tasks_long'),
)
CELERY_DEFAULT_QUEUE = 'default'
CELERY_DEFAULT_EXCHANGE_TYPE = 'topic'
CELERY_DEFAULT_ROUTING_KEY = 'default'
CELERY_ROUTES = {
    'network_monitor.core.tasks.check_device_status_periodic': {
        'queue': 'periodic_tasks_long',
        'routing_key': 'periodic_tasks_long',
    },
    'network_monitor.core.tasks.check_alert_rules_periodic': {
        'queue': 'periodic_tasks',
        'routing_key': 'periodic_tasks',
    },
}

# Google social auth2 setting
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '<GOOGLE_OAUTH2_KEY.apps.googleusercontent.com>'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = '<GOOGLE_OAUTH2_SECRET>'

SOCIAL_AUTH_LOGIN_URL = LOGIN_URL
SOCIAL_AUTH_LOGIN_REDIRECT_URL = LOGIN_REDIRECT_URL
SOCIAL_AUTH_PIPELINE = (
    'social.pipeline.social_auth.social_details',
    'social.pipeline.social_auth.social_uid',
    'social.pipeline.social_auth.auth_allowed',
    'social.pipeline.social_auth.social_user',
    'social.pipeline.user.get_username',
    'social.pipeline.social_auth.associate_by_email',
    'social.pipeline.user.create_user',
    'social.pipeline.social_auth.associate_user',
    'social.pipeline.social_auth.load_extra_data',
    'social.pipeline.user.user_details',
)

CKEDITOR_CONFIGS = {
    'default': {
        'skin': 'moono',
        'toolbar_Basic': [
            ['Source', '-', 'Bold', 'Italic']
        ],
        'toolbar_Full': [
            ['Styles', 'Format', 'Bold', 'Italic', 'Underline', 'Strike', 'SpellChecker', 'Undo', 'Redo'],
            ['Link', 'Unlink', 'Anchor'],
            ['Table', 'HorizontalRule'],
            ['TextColor', 'BGColor'],
            ['Smiley', 'SpecialChar'], ['Source'],
        ],
        'toolbar': 'Full',
        'height': 291,
        'width': 835,
        'filebrowserWindowWidth': 940,
        'filebrowserWindowHeight': 725,
    },
    'awesome': {
        'skin': 'moono',
        'toolbar_Basic': [
            ['Source', '-', 'Bold', 'Italic']
        ],
        'toolbar_Full': [
            ['Styles', 'Format', 'Font', 'FontSize', 'Bold', 'Italic', 'Underline', 'Strike', 'Subscript', 'Superscript', '-', 'RemoveFormat', 'Undo', 'Redo'],
            ['Link', 'Unlink', 'Anchor'],
            ['Table', 'HorizontalRule'],
            ['NumberedList', 'BulletedList', "Indent", "Outdent"],
            ['JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock',],
            ['TextColor', 'BGColor'],
            ['Smiley', 'SpecialChar'], ['Source', 'ShowBlocks'], ['Preview', "Maximize"],
            ['vartags']
        ],
        'htmlbuttons': [{
            'name': 'vartags',
            'icon': 'bracket.png',
            'title': 'Insert Dynamic Variables',
            'items': [
                {'name': 'device_name', 'html': '{device_name}', 'title': '{device_name}'},
                {'name': 'device_address', 'html': '{device_address}', 'title': '{device_address}'},
                {'name': 'threshold_name', 'html': '{threshold_name}', 'title': '{threshold_name}'},
                {'name': 'threshold_type', 'html': '{threshold_type}', 'title': '{threshold_type}'},
                {'name': 'feature', 'html': '{feature}', 'title': '{feature}'},
                {'name': 'event_severity', 'html': '{event_severity}', 'title': '{event_severity}'},
                {'name': 'event_summary', 'html': '{event_summary}', 'title': '{event_summary}'},
                {'name': 'event_message', 'html': '{event_message}', 'title': '{event_message}'},
                {'name': 'event_time', 'html': '{event_time}', 'title': '{event_time}'},
            ]
        },],
        'toolbar': 'Full',
        'extraPlugins': ','.join(['htmlbuttons']),
        'height': 291,
        'width': 835,
        'autoParagraph': False,
        'filebrowserWindowWidth': 940,
        'filebrowserWindowHeight': 725,
    }

}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[%(asctime)s] %(levelname)s %(pathname)s:%(lineno)d %(message)s'
        },
        'simple': {
            'format': '[%(asctime)s] %(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
            'formatter': 'verbose',
        }
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'propagate': True,
        },
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
    }
}

# CACHES = {
#     "default": {
#         "BACKEND": "django_redis.cache.RedisCache",
#         "LOCATION": "redis://127.0.0.1:6379/1",
#         "TIMEOUT": 3600,  # 1 hour,
#         "KEY_PREFIX": "django-network-monitor::",
#         "OPTIONS": {
#             "CLIENT_CLASS": "django_redis.client.DefaultClient",
#         }
#     }
# }

# dbbackup settings
DBBACKUP_STORAGE = 'django.core.files.storage.FileSystemStorage'

##############################
#  network_monitor settings  #
##############################
EMAIL_MOCK_SENDING = False
SMS_MOCK_SENDING = False
# we use HOSTNAME to create external links outside of django request
HOSTNAME = 'localhost'
DEFAULT_EMAIL_FROM = 'info@networkmonitor.io'

MON_SERVICE_INTERVAL = 20
ENABLE_REGISTER_USER_VIEW = False

# RedisMem settings
REDIS_MEM_HOST = 'localhost'
REDIS_MEM_PORT = 6379
REDIS_MEM_DB = 1
REDIS_MEM_PREFIX = 'network-monitor:'
REDIS_MEM_DEFAULT_EXPIRE = 600

MACVENDORS_API_URL = 'http://api.macvendors.com/'
MACVENDORS_API_TIMEOUT = 5
