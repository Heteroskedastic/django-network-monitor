from django.conf import settings
from twilio.rest import TwilioRestClient

from network_monitor.redis_mem import RedisMem


def get_twilio_client():
    return TwilioRestClient(settings.TWILIO_ACCOUNT_SID,
                            settings.TWILIO_AUTH_TOKEN)


def get_redis_mem(workspace):
    return RedisMem(host=settings.REDIS_MEM_HOST,
                    port=settings.REDIS_MEM_PORT,
                    db=settings.REDIS_MEM_DB,
                    prefix=settings.REDIS_MEM_PREFIX,
                    workspace=workspace)


def get_installed_features():
    return [a.split('.')[-3] for a in settings.INSTALLED_FEATURES]
