from .base import *

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'test',
        'TEST_NAME': 'travis_ci_test',
    }
}

EMAIL_MOCK_SENDING = True
SMS_MOCK_SENDING = True
