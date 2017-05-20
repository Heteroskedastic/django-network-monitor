import time
from django.conf import settings
from django.core.management.base import BaseCommand

from network_monitor.core.models import DeviceFeature
from network_monitor.core.tasks import feature_mon_handle
from network_monitor.helpers.shortcuts import get_redis_mem, get_installed_features


class Command(BaseCommand):

    help = "Start monitoring service.\n"\
           "Usage: python manage.py mon_service [OPTIONS]. \n"
    label = 'file(s)'

    def add_arguments(self, parser):
        parser.add_argument('--interval', action='store', type=int,
                            default=0)

    def handle(self, *args, **options):
        interval = options.get('interval') or settings.MON_SERVICE_INTERVAL

        self._paused = False
        redis_mem = get_redis_mem('feature_mon_handle')
        redis_mem.clean()
        while not self._paused:
            try:
                print("++++++++++++ Starting Round....")
                self._work()
                print("------------ Finished Round....")
                print("!! Waiting for {} second !!".format(interval))
                time.sleep(interval)
            except KeyboardInterrupt:
                print('Finished by KeyboardInterrupt!')
                break

    def _work(self):
        features = get_installed_features()
        query = DeviceFeature.objects.values_list('pk', flat=True).\
            filter(feature__in=features, active=True, device__active=True).\
            extra(where=["last_round is NULL or (last_round<NOW() - "
                         "(round_interval || ' seconds')::interval)"])
        q_count = query.count()
        if q_count == 0:
            print('No feature found for this round!')
            return
        print('***** Processing {} device features'.format(q_count))
        redis_mem = get_redis_mem('feature_mon_handle')
        for df_id in query:
            if not redis_mem.get(str(df_id)):
                feature_mon_handle.delay(df_id)
                redis_mem.set(str(df_id), True, expire=settings.REDIS_MEM_DEFAULT_EXPIRE)
            else:
                print('device feature #{} is already in queue!'.format(df_id))
