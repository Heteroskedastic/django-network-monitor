from django.contrib import admin
from .models import Device, DeviceFeature, Threshold, Event, UserProfile


admin.site.register(Device)
admin.site.register(DeviceFeature)
admin.site.register(Threshold)
admin.site.register(Event)
admin.site.register(UserProfile)
