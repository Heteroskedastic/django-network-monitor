import logging
from django.utils import timezone
from network_monitor.core.models import Event, SEVERITY_CLEAR


class BaseMonHandler(object):
    def __init__(self, device_feature, logger=None):
        self.device_feature = device_feature
        self.logger = logger or logging

    def do_round(self):
        return NotImplementedError

    def get_last_data(self):
        return getattr(self, 'last_data', None)

    def check_thresholds(self):
        last_data = self.get_last_data()
        if not last_data:
            self.logger.warning('%s: last data is not fetched!', self)
            return

        thresholds = self.device_feature.threshold.filter(active=True).all()
        self.logger.info('**** %s: checking [%s] thresholds',
                         self.device_feature, len(thresholds))
        for threshold in thresholds:
            self.logger.info('----: checking [%s] threshold', threshold)
            threshold_obj = threshold.threshold_object
            evt_args = dict(
                device=self.device_feature.device,
                feature=self.device_feature.feature,
                threshold=threshold,
                severity=threshold.severity,
                summary=threshold_obj.trigger_short_message,
                message=threshold_obj.trigger_message,
            )

            if threshold_obj.satisfied(last_data):
                self.logger.info('!!!!! [%s] threshold satisfied', threshold)
                threshold.trigger()
                Event.create_or_update(**evt_args)
                threshold.save()
            elif not threshold.clear_time and threshold.trigger_time:
                threshold.event.filter(clear_time=None).update(clear_time=timezone.now())
                self.logger.info('!!!!! [%s] threshold cleared', threshold)
                threshold.clear()
                evt_args['severity'] = SEVERITY_CLEAR
                evt_args['summary'] = threshold_obj.clear_short_message
                evt_args['message'] = threshold_obj.clear_message
                Event.objects.create(**evt_args)
                threshold.save()

    def handle(self):
        self.do_round()
        self.check_thresholds()

    def __str__(self):
        return '{}({})'.format(self.__class__.__name__, self.device_feature)
