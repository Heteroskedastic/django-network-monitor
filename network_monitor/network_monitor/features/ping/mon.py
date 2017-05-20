import subprocess
try:
    from network_monitor.helpers.utils import py2_subprocess_run as subprocess_run
except ImportError:
    from subprocess import run as subprocess_run
from django.utils import timezone

from network_monitor.monit_manager.handler import BaseMonHandler
from .models import PingTime


def ping_parse(output):
    output = output.split('\n')[-3:]
    packet_loss = float(output[0].split("%")[0].split()[-1])
    ping_min = ping_avg = ping_max = ping_mdev = None
    if len(output) > 1 and 'avg' in output[1]:
        timing_stats = output[1].rstrip('ms').split("=")[1].split("/")
        ping_min = float(timing_stats[0])
        ping_avg = float(timing_stats[1])
        ping_max = float(timing_stats[2])
        ping_mdev = float(timing_stats[3])
    return dict(min_time=ping_min, max_time=ping_max, avg_time=ping_avg,
                mdev_time=ping_mdev, packet_loss=packet_loss)


class MonHandler(BaseMonHandler):
    def do_round(self):
        device = self.device_feature.device
        ping_count = (self.device_feature.args or {}).get('ping_count') or 2
        address = device.address
        cmd = "/bin/ping -n -q -c {ping_count} {address}".format(
            ping_count=ping_count, address=address)
        self.logger.info('Running command >>> %s', cmd)
        result = subprocess_run(cmd, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        output = result.stdout.decode()
        err = result.stderr.decode()
        if not output:
            self.logger.error(err)
            return

        ping_data = ping_parse(output)
        PingTime.objects.create(device=device, **ping_data)
        if ping_data['packet_loss'] == 100:
            device.status = device.STATUS_DOWN
        else:
            device.status = device.STATUS_UP
            device.last_seen = timezone.now()
        device.save(update_fields=["status", "last_seen"])
        self.last_data = ping_data
