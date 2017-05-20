from django.apps import AppConfig


class PingConfig(AppConfig):
    name = 'network_monitor.features.ping'
    verbose_name = 'Ping IP Checking'

    @property
    def mon_handler_class(self):
        from .mon import MonHandler
        return MonHandler

    @property
    def mon_config(self):
        return {
            'threshold': {
                'types': {
                    'MinMaxThreshold': {
                        'valid_parameters': [
                            'min_time', 'max_time', 'avg_time', 'mdev_time', 'packet_loss'
                        ],
                    },
                }
            }
        }
