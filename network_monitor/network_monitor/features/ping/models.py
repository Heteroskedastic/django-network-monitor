from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator

from network_monitor.core.models import Device


class PingTime(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE,
                               related_name='ping_time')
    min_time = models.FloatField('Minimum Time(ms)', null=True)
    max_time = models.FloatField('Maximum Time(ms)', null=True)
    avg_time = models.FloatField('Avgerage Time(ms)', null=True)
    mdev_time = models.FloatField('Median Deviation(ms)', null=True)
    packet_loss = models.FloatField('Packet Loss(%)', default=0.0,
                                    validators=[MinValueValidator(0.0),
                                                MaxValueValidator(100.0)])
    timestamp = models.DateTimeField('Timestamp', default=timezone.now)

    def __str__(self):
        return 'Ping(device={}, Loss={})'.format(self.device, self.packet_loss)
