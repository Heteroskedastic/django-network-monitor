from django.contrib import admin
from .models import Device, DeviceFeature, Threshold, Event, UserProfile, UserAlertRule

admin.site.register(Device)
admin.site.register(DeviceFeature)
admin.site.register(Threshold)
admin.site.register(Event)
admin.site.register(UserProfile)
admin.site.register(UserAlertRule)
