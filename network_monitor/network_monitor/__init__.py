from __future__ import absolute_import

from .celery import app as celery_app
from django.core import mail
from django.conf import settings


def mock_send_mail(*args, **kwargs):
    print("Sending email: {0}, {1}".format(args, kwargs))

if settings.EMAIL_MOCK_SENDING:
    mail.send_mail = mock_send_mail
