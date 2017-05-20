"""network_monitor URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls import url, include
from django.contrib import admin
from network_monitor.core.views import DeviceFeatureConfigView, DeviceFeatureChartsView, \
    DeviceFeatureThresholdListView, DeviceFeatureThresholdDeleteView, \
    DeviceFeatureThresholdSwitchView, DeviceFeatureThresholdAddView


urlpatterns = [
    url(r'^', include('social.apps.django_app.urls', namespace='social')),
    url(r'^admin/', admin.site.urls),
    url(r'', include('network_monitor.core.urls', namespace='core')),
]
for app in settings.INSTALLED_FEATURES:
    f = app.split('.')[-3]
    app_urls = '.'.join(app.split('.')[:-2]+['urls'])
    urlpatterns.append(url(r'^device/(?P<device_id>\d+)/{}/'.format(f), include(app_urls), kwargs={'feature': f}))

# default device_features routing
urlpatterns.extend([
    url(r'^device/(?P<device_id>\d+)/(?P<feature>.+)/config/$',
        DeviceFeatureConfigView.as_view(), name="device-feature-config"),
    url(r'^device/(?P<device_id>\d+)/(?P<feature>.+)/charts/$',
        DeviceFeatureChartsView.as_view(), name="device-feature-charts"),
    url(r'^device/(?P<device_id>\d+)/(?P<feature>.+)/threshold/list/$',
        DeviceFeatureThresholdListView.as_view(),
        name="device-feature-threshold-list"),
    url(r'^device/(?P<device_id>\d+)/(?P<feature>.+)/threshold/add/(?P<threshold_type>.+)/$',
        DeviceFeatureThresholdAddView.as_view(),
        name="device-feature-threshold-add"),
    url(r'^device/(?P<device_id>\d+)/(?P<feature>.+)/threshold/delete/(?P<threshold_id>\d+)/$',
        DeviceFeatureThresholdDeleteView.as_view(),
        name="device-feature-threshold-delete"),
    url(r'^device/(?P<device_id>\d+)/(?P<feature>.+)/threshold/switch/(?P<threshold_id>\d+)/$',
        DeviceFeatureThresholdSwitchView.as_view(),
        name="device-feature-threshold-switch"),
])
