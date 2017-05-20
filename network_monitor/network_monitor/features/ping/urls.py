from django.conf.urls import url

from .views import DeviceFeatureConfigView, DeviceFeatureChartsView


urlpatterns = [
    url(r'^config/$',
        DeviceFeatureConfigView.as_view(), name="device-feature-config"),
    url(r'^charts/$',
        DeviceFeatureChartsView.as_view(), name="device-feature-charts"),

]
