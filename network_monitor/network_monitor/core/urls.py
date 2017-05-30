from django.conf.urls import url
from django.conf import settings

from network_monitor.helpers.utils import NotFoundView
from .views import IndexView, RegisterView, LoginView, LogoutView, \
    ProfileView, ChangePasswordView, DeviceListView, DeviceAddView, \
    DeviceEditView, DeviceDeleteView, DeviceFeaturesView, EventListView, \
    EventDeleteView, UserAlertRuleListView, UserAlertRuleAddView, \
    UserAlertRuleEditView, UserAlertRuleDeleteView, DeviceSwitchActiveView, UserAlertRuleSwitchActiveView, \
    DevicesStatusAjaxView, DevicePrintLabelView, DiscoverDeviceView

urlpatterns = [
    url(r'^$', IndexView.as_view(), name='index'),
    url(r'^register/$', (RegisterView if settings.ENABLE_REGISTER_USER_VIEW else NotFoundView).as_view(),
        name="register"),
    url(r'^login/$', LoginView.as_view(), name="login"),
    url(r'^logout/$', LogoutView.as_view(), name="logout"),
    url(r'^profile/$', ProfileView.as_view(), name="profile"),
    url(r'^change-password/$', ChangePasswordView.as_view(), name="change-password"),
    url(r'^event/list/$', EventListView.as_view(), name="event-list"),
    url(r'^event/delete/(?P<pk>\d+)/$', EventDeleteView.as_view(), name="event-delete"),
    url(r'^device/list/$', DeviceListView.as_view(), name="device-list"),
    url(r'^device/add/$', DeviceAddView.as_view(), name="device-add"),
    url(r'^device/discover/$', DiscoverDeviceView.as_view(), name="device-discover"),
    url(r'^device/edit/(?P<pk>\d+)/$', DeviceEditView.as_view(), name="device-edit"),
    url(r'^device/switch-active/(?P<pk>\d+)/$', DeviceSwitchActiveView.as_view(), name="device-switch-active"),
    url(r'^device/delete/(?P<pk>\d+)/$', DeviceDeleteView.as_view(), name="device-delete"),
    url(r'^device/print-label/(?P<pk>\d+)/$', DevicePrintLabelView.as_view(), name="device-print-label"),
    url(r'^device/features/(?P<pk>\d+)/$', DeviceFeaturesView.as_view(), name="device-features"),
    url(r'^device/status/(?P<pk>((\d+),?)+)/$', DevicesStatusAjaxView.as_view(), name="device-status"),
    url(r'^user_alert_rule/list/$', UserAlertRuleListView.as_view(), name="user_alert_rule-list"),
    url(r'^user_alert_rule/add/$', UserAlertRuleAddView.as_view(), name="user_alert_rule-add"),
    url(r'^user_alert_rule/edit/(?P<pk>\d+)/$', UserAlertRuleEditView.as_view(), name="user_alert_rule-edit"),
    url(r'^user_alert_rule/switch-active/(?P<pk>\d+)/$', UserAlertRuleSwitchActiveView.as_view(), name="user_alert_rule-switch-active"),
    url(r'^user_alert_rule/delete/(?P<pk>\d+)/$', UserAlertRuleDeleteView.as_view(), name="user_alert_rule-delete"),
]
