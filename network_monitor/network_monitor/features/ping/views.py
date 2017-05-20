from django.db.models import Avg, Min, Max
from datetime import timedelta
from django.utils import timezone
from django.utils.dateparse import parse_date

from network_monitor.core.views import DeviceFeatureConfigView as CoreDeviceFeatureConfigView
from network_monitor.core.views import DeviceFeatureChartsView as CoreDeviceFeatureChartsView
from .models import PingTime


class DeviceFeatureConfigView(CoreDeviceFeatureConfigView):
    template_name = 'network_monitor/ping/device_feature/config.html'


class DeviceFeatureChartsView(CoreDeviceFeatureChartsView):
    template_name = 'network_monitor/ping/device_feature/charts.html'
    chart_date = None

    def get_context_data(self, **kwargs):
        ctx = super(DeviceFeatureChartsView, self).get_context_data(**kwargs)
        ctx['chart_date'] = self._get_chart_date()
        return ctx

    def _get_chart_date(self):
        if not self.chart_date:
            chart_date = self.request.GET.get('chart_date')
            today = timezone.now().date()
            if not chart_date:
                return today
            if chart_date.isdigit():
                return today - timedelta(days=int(chart_date))
            date = parse_date(chart_date)
            self.chart_date = date or today
        return self.chart_date

    def get_chart_data(self):
        device = self.device_object
        packet_loss_data = []
        ping_time_data = []
        date = self._get_chart_date()
        query = PingTime.objects.filter(
            device=device, timestamp__contains=date).order_by('timestamp')
        for r in query:
            packet_loss_data.append({'timestamp': str(r.timestamp),
                                     'packet_loss': r.packet_loss})
            ping_time_data.append({
                'timestamp': str(r.timestamp), 'min_time': r.min_time,
                'max_time': r.max_time, 'avg_time': r.avg_time,
                'mdev_time': r.mdev_time
            })
        return {
            'packet_loss': packet_loss_data, 'ping_time': ping_time_data
        }

    def get_report_data(self):
        now = timezone.now()
        device = self.device_object
        last = PingTime.objects.filter(device=device
                                       ).order_by('timestamp').last()

        data = {
            'last_record': {
                'min_time': last and last.min_time,
                'max_time': last and last.max_time,
                'avg_time': last and last.avg_time,
                'packet_loss': last and last.packet_loss
            }
        }
        periods = {
            'last_hour': timedelta(hours=1),
            'last_24_hours': timedelta(hours=24),
            'last_7_days': timedelta(days=7),
            'last_30_days': timedelta(days=30),
        }
        query = PingTime.objects.filter(device=device)
        for title, period in periods.items():
            res = query.filter(
                timestamp__gte=now - period).aggregate(
                avg_time=Avg('avg_time'), min_time=Min('min_time'),
                max_time=Max('max_time'), packet_loss=Avg('packet_loss'))
            data[title] = res
        return data
