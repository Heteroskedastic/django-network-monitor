import json
import subprocess

from django.contrib.humanize.templatetags.humanize import naturaltime
from django.db.models import Q
from django.http import HttpResponseRedirect, HttpResponse
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.core.urlresolvers import reverse
from django.http import Http404
from django.views.generic.base import TemplateView
from django.views.generic import View
from django.views.generic.edit import UpdateView
from django.conf import settings
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.views import password_change
from django.views.generic.edit import CreateView
from django.views.generic.detail import SingleObjectMixin
from dynamic_preferences.forms import global_preference_form_builder
from dynamic_preferences.registries import global_preferences_registry

from network_monitor.celery import app
from network_monitor.helpers.shortcuts import get_redis_mem
from network_monitor.core.tasks import nmap_scan_network
from network_monitor.helpers.utils import send_form_errors, success_message, \
    PermissionRequiredMixin, get_current_page_size, find_mac_manufacture, to_dict, warning_message
from .forms import RegistrationForm, LoginForm, ProfileForm, DeviceForm, \
    DeviceFeatureForm, ThresholdForm, UserAlertRuleForm, DiscoverDeviceForm, DeviceFixMacForm
from .filters import DevicesFilter, EventsFilter
from .models import Device, DeviceFeature, Threshold, Event, UserAlertRule, \
    SEVERITY_CHOICES
try:
    from network_monitor.helpers.utils import py2_subprocess_run as subprocess_run
except ImportError:
    from subprocess import run as subprocess_run


class IndexView(PermissionRequiredMixin, View):
    permission_required = ()

    def get(self, request, *args, **kwargs):
        ctx = {}
        return render(request, "network_monitor/core/index.html", ctx)


class RegisterView(View):

    def get(self, request, *args, **kwargs):
        form = RegistrationForm()
        ctx = {"form": form}
        return render(request, "network_monitor/core/register.html", ctx)

    def post(self, request, *args, **kwargs):
        form = RegistrationForm(request.POST)
        password = request.POST.get('password')
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(password)
            user.save()
            success_message('User registered successfully', request)
            return redirect(self.get_success_url())
        else:
            send_form_errors(form, request)
        ctx = {"form": form}
        return render(request, "network_monitor/core/register.html", ctx)

    def get_success_url(self):
        return settings.LOGIN_URL


class LoginView(View):
    template_name = "network_monitor/core/login.html"

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated():
            return redirect(settings.LOGIN_REDIRECT_URL)
        form = LoginForm()
        ctx = {"form": form}
        return render(request, self.template_name, ctx)

    def post(self, request, *args, **kwargs):
        form = LoginForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            auth_login(request, user)
            next = request.GET.get('next') or settings.LOGIN_REDIRECT_URL
            return redirect(next)
        else:
            send_form_errors(form, request)
        ctx = {"form": form}
        return render(request, self.template_name, ctx)


class LogoutView(View):

    def get(self, request, *args, **kwargs):
        auth_logout(request)
        return redirect(settings.LOGIN_URL)


class ProfileView(PermissionRequiredMixin, UpdateView):
    permission_required = ()
    form_class = ProfileForm
    template_name = 'network_monitor/core/profile.html'

    def get_object(self, queryset=None):
        return self.request.user

    def form_valid(self, form):
        result = super(ProfileView, self).form_valid(form)
        success_message('Profile updated successfully.', self.request)
        return result

    def get_initial(self):
        profile = self.object.profile
        return {
            field: getattr(profile, field, None)
            for field in self.form_class.Meta._profile_fields
        }

    def get_success_url(self):
        return reverse('core:profile')


class ChangePasswordView(PermissionRequiredMixin, View):
    permission_required = ()

    def get(self, request, *args, **kwargs):
        self.get_success_url()
        return password_change(
            request, template_name='network_monitor/core/change_password.html',
            post_change_redirect=self.get_success_url(),)

    def post(self, request, *args, **kwargs):
        redirect_url = self.get_success_url()
        response = password_change(
            request, template_name='network_monitor/core/change_password.html',
            post_change_redirect=redirect_url)
        if response.status_code == 302 and response.url == redirect_url:
            success_message('Password changed successfully.', request)
        return response

    def get_success_url(self):
        return reverse('core:profile')


class DeviceListView(PermissionRequiredMixin, View):
    permission_required = 'core.view_device'

    def get(self, request, *args, **kwargs):
        qs = Device.objects.order_by('-active', 'id', )
        devices = DevicesFilter(self.request.GET, queryset=qs)
        ctx = {'devices': devices, 'page_size': get_current_page_size(request)}
        return render(request, "network_monitor/core/device/list.html", ctx)


class DeviceAddView(PermissionRequiredMixin, CreateView):
    permission_required = 'core.add_device'
    form_class = DeviceForm
    template_name = 'network_monitor/core/device/add.html'

    def get_form(self, form_class=None):
        form = super(DeviceAddView, self).get_form(form_class=form_class)
        if not self.request.user.has_perm("core.access_device_secret_data"):
            for sf in Device.secret_fields():
                form.fields.pop(sf, None)
        return form

    def form_invalid(self, form):
        if self.request.is_ajax():
            return JsonResponse({'message': 'Invalid parameters', 'errors': form.errors}, status=400)
        return super(DeviceAddView, self).form_invalid(form)

    def form_valid(self, form):
        self.object = form.save(commit=False)
        if self.object.mac:
            self.object.mac_manufacture = self.object.fetch_mac_manufacture()
        self.object.save()
        if self.request.is_ajax():
            return JsonResponse(to_dict(self.object, fields=['id', 'name', 'address', 'mac']))

        success_message('Device "{}" created successfully.'.format(self.object), self.request)
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return reverse('core:device-list')


class DeviceEditView(PermissionRequiredMixin, UpdateView):
    permission_required = {
        'get': 'core.view_device',
        'post': 'core.change_device'
    }
    pk_url_kwarg = 'pk'
    form_class = DeviceForm
    model = Device
    template_name = 'network_monitor/core/device/edit.html'

    def get_form(self, form_class=None):
        form = super(DeviceEditView, self).get_form(form_class=form_class)
        if not self.request.user.has_perm("core.access_device_secret_data"):
            for sf in Device.secret_fields():
                form.fields.pop(sf, None)
        return form

    def form_invalid(self, form):
        if self.request.is_ajax():
            return JsonResponse({'message': 'Invalid parameters', 'errors': form.errors}, status=400)
        return super(DeviceEditView, self).form_invalid(form)

    def form_valid(self, form):
        self.object = form.save(commit=False)
        if 'mac' in form.changed_data or not self.object.mac_manufacture:
            self.object.mac_manufacture = self.object.fetch_mac_manufacture()
        self.object.save()
        if self.request.is_ajax():
            return JsonResponse(to_dict(self.object, fields=['id', 'name', 'address', 'mac']))

        success_message('Device "{}" updated successfully.'.format(self.object), self.request)
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return reverse('core:device-list')


class DeviceFixMacView(PermissionRequiredMixin, UpdateView):
    permission_required = {
        'get': 'core.view_device',
        'post': 'core.change_device'
    }
    pk_url_kwarg = 'pk'
    form_class = DeviceFixMacForm
    model = Device

    def form_invalid(self, form):
        return JsonResponse({'message': 'Invalid parameters', 'errors': form.errors}, status=400)

    def form_valid(self, form):
        self.object = form.save(commit=False)
        self.object.mac_manufacture = self.object.fetch_mac_manufacture()
        self.object.save()
        return JsonResponse(to_dict(self.object, fields=['id', 'name', 'address', 'mac']))


class DiscoverDeviceView(PermissionRequiredMixin, View):
    permission_required = 'core.add_device'
    template_name = "network_monitor/core/device/discover.html"

    def get_form(self):
        data = None
        if self.request.method == 'POST':
            data = self.request.POST
        return DiscoverDeviceForm(data=data)

    @staticmethod
    def _get_discovered_devices(scan):
        discovered_devices = []
        for ip, data in scan.items():
            mac = data.get('vendor', {}).get('mac')
            hostnames = [d.get('name') for d in data.get('hostnames', []) if d.get('name') ]
            status = 'new'
            manufacture = None
            if mac:
                device = Device.objects.filter(Q(address=ip)|Q(mac=mac)).first()
            else:
                device = Device.objects.filter(address=ip).first()
            if device:
                if mac and (device.mac != mac):
                    status = 'conflict'
                else:
                    status = 'existing'
                    manufacture = device.mac_manufacture or device.fetch_mac_manufacture()
            if mac and not manufacture:
                manufacture = find_mac_manufacture(mac)
            discovered_devices.append(
                {'ip': ip, 'mac': mac, 'manufacture': manufacture, 'hostnames': hostnames, 'status': status,
                 'obj': device})
        status_orders = {'new': 1, 'conflict': 2, 'existing': 3}
        discovered_devices.sort(key=lambda d: (status_orders.get(d['status'], 0), d['ip']))
        return discovered_devices

    def get_last_scan(self):
        redis_mem = get_redis_mem('nmap_scan_network')
        last_scan = redis_mem.get(str(self.request.user.id)) or {}
        scan_result = last_scan.pop('result', {})
        last_scan['discovered_devices'] = self._get_discovered_devices(scan_result)
        return last_scan

    def get_context_data(self, **kwargs):
        kwargs.update({'last_scan': self.get_last_scan()})
        return kwargs

    def get(self, request, *args, **kwargs):
        if request.is_ajax():
            last_scan = self.get_last_scan()
            if request.GET.get('exclude_devices'):
                last_scan.pop('discovered_devices', None)
            return JsonResponse(last_scan)
        ctx = self.get_context_data(form=self.get_form())
        return render(request, self.template_name, ctx)

    def post(self, request, *args, **kwargs):
        user_id = request.user.id
        redis_mem = get_redis_mem('nmap_scan_network')
        last_scan = redis_mem.get(str(user_id)) or {}
        if last_scan.get('processing'):
            warning_message('Network is already under scanning!', request)
            return redirect('core:device-discover')
        if last_scan:
            redis_mem.delete(str())

        form = self.get_form()
        if form.is_valid():
            ip_range = form.cleaned_data['ip_range']
            task = nmap_scan_network.delay(user_id, ip_range)
            redis_mem.set(str(user_id), {'ip_range': ip_range, 'processing': True, 'task_id': task.task_id},
                          expire=settings.REDIS_MEM_DEFAULT_EXPIRE)
            return redirect('core:device-discover')
        else:
            send_form_errors(form, request)
            ctx = self.get_context_data(form=form)
            return render(request, self.template_name, ctx)


class StopDiscoverDeviceView(PermissionRequiredMixin, View):
    permission_required = 'core.add_device'

    def post(self, request, *args, **kwargs):
        user_id = request.user.id
        redis_mem = get_redis_mem('nmap_scan_network')
        last_scan = redis_mem.get(str(user_id)) or {}
        if not last_scan.get('processing'):
            raise JsonResponse({'message': 'No process under scanning!'}, status=400)
        task_id = last_scan.get('task_id')
        app.control.revoke(task_id, terminate=True)
        redis_mem.delete(str(user_id))
        return JsonResponse({'task_id': task_id})


class DeviceSwitchActiveView(PermissionRequiredMixin, SingleObjectMixin, View):
    permission_required = 'core.change_device'
    pk_url_kwarg = 'pk'
    model = Device

    def post(self, request, *args, **kwargs):
        device = self.get_object()
        device.active = not device.active
        device.save()
        status = 'Enabled' if device.active else 'Disabled'
        success_message(
            'Device "{}" {} successfully!'.format(device, status),
            self.request)
        return redirect(self.get_success_url())

    def get_success_url(self):
        return reverse('core:device-list')


class DeviceDeleteView(PermissionRequiredMixin, SingleObjectMixin, View):
    permission_required = 'core.delete_device'
    pk_url_kwarg = 'pk'
    model = Device

    def post(self, request, *args, **kwargs):
        device = self.get_object()
        device.delete()
        success_message(
            'Device "{}" deleted successfully!'.format(device),
            self.request)
        return redirect(reverse('core:device-list'))


class DevicePrintLabelView(PermissionRequiredMixin, SingleObjectMixin, View):
    permission_required = 'core.view_device'
    pk_url_kwarg = 'pk'
    model = Device

    def get(self, request, *args, **kwargs):
        device = self.get_object()
        ctx = {'device': device}
        return render(request, "network_monitor/core/device/print-label.html", ctx)


class DeviceFeaturesView(PermissionRequiredMixin, SingleObjectMixin, View):
    permission_required = 'core.view_devicefeature'
    pk_url_kwarg = 'pk'
    model = Device

    def get(self, request, *args, **kwargs):
        device = self.get_object()
        all_features = [f[0] for f in DeviceFeature.FEATURE_CHOICES]
        device_features = DeviceFeature.objects.filter(device=device, feature__in=all_features)
        feature_map = {df.feature: df for df in device_features}
        for f in all_features:
            if f not in feature_map:
                feature_map[f] = DeviceFeature.objects.create(device=device,
                                                              feature=f)
        features = list(feature_map.values())
        features.sort(key=lambda f: (f.active, f.feature), reverse=True)

        ctx = {'features': features, 'device': device}
        return render(request, "network_monitor/core/device/features.html", ctx)


class DevicesStatusAjaxView(PermissionRequiredMixin, View):
    permission_required = 'core.view_device'
    pk_url_kwarg = 'pk'

    def get_ids(self):
        return [int(i) for i in self.kwargs.get(self.pk_url_kwarg).rstrip(',').split(',')]

    def get(self, request, *args, **kwargs):
        device_ids = self.get_ids()
        devices = {}
        for d in Device.objects.filter(id__in=device_ids):
            devices[d.pk] = {
                'status': d.status,
                'last_seen': d.last_seen,
                'last_seen_humanize': naturaltime(d.last_seen),
            }

        return JsonResponse({'devices': devices})


class PingTestDeviceView(PermissionRequiredMixin, SingleObjectMixin, View):
    permission_required = 'core.ping_test_device'
    pk_url_kwarg = 'pk'
    model = Device

    def post(self, request, *args, **kwargs):
        device = self.get_object()
        cmd = "/bin/ping -n -c 5 -W 1 {address}".format(address=device.address)
        result = subprocess_run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response = result.stdout.decode()
        status = 'success'
        if not response:
            status = 'error'
            response = result.stderr.decode()

        return JsonResponse({'data': response, 'status': status})


class EventListView(PermissionRequiredMixin, View):
    permission_required = 'core.view_event'

    def get(self, request, *args, **kwargs):
        qs = Event.objects.order_by('-last_time')
        events = EventsFilter(self.request.GET, queryset=qs)
        ctx = {'events': events, 'page_size': get_current_page_size(request)}
        return render(request, "network_monitor/core/event/list.html", ctx)


class EventDeleteView(PermissionRequiredMixin, SingleObjectMixin, View):
    permission_required = 'core.delete_event'
    pk_url_kwarg = 'pk'
    model = Event

    def post(self, request, *args, **kwargs):
        event = self.get_object()
        event_id = event.id
        event.delete()
        success_message(
            'Event "#{}" deleted successfully!'.format(event_id),
            self.request)
        return redirect(self.get_success_url())

    def get_success_url(self):
        url = self.request.META.get('HTTP_REFERER') or ''
        if '/event/list' not in url:
            url = reverse('core:event-list')
        return url


class UserAlertRuleListView(PermissionRequiredMixin, View):
    permission_required = 'core.view_useralertrule'

    def get(self, request, *args, **kwargs):
        rules = UserAlertRule.objects.filter(user=request.user).order_by('id')
        ctx = {'alert_rules': rules}
        return render(request, "network_monitor/core/user_alert_rule/list.html", ctx)


class UserAlertRuleSwitchActiveView(PermissionRequiredMixin, SingleObjectMixin, View):
    permission_required = 'core.change_useralertrule'
    pk_url_kwarg = 'pk'
    model = UserAlertRule

    def post(self, request, *args, **kwargs):
        rule = self.get_object()
        rule.active = not rule.active
        rule.save()
        status = 'Enabled' if rule.active else 'Disabled'
        success_message(
            'Rule "{}" {} successfully!'.format(rule, status),
            self.request)
        return redirect(self.get_success_url())

    def get_success_url(self):
        return reverse('core:user_alert_rule-list')


def user_alert_rule_contxt():
    ctx = {}
    ctx['device_choices'] = json.dumps(
        [(d.id, d.name) for d in Device.objects.order_by('id').all()])
    ctx['feature_choices'] = json.dumps(DeviceFeature.FEATURE_CHOICES)
    ctx['threshold_choices'] = json.dumps(
        [(t.id, t.name) for t in Threshold.objects.order_by('id')])
    ctx['severity_choices'] = json.dumps(SEVERITY_CHOICES)
    return ctx


class UserAlertRuleAddView(PermissionRequiredMixin, CreateView):
    permission_required = 'core.add_useralertrule'
    form_class = UserAlertRuleForm
    template_name = 'network_monitor/core/user_alert_rule/add.html'

    def get_context_data(self, **kwargs):
        ctx = super(UserAlertRuleAddView, self).get_context_data(**kwargs)
        ctx.update(user_alert_rule_contxt())
        return ctx

    def form_valid(self, form):
        self.object = form.save(commit=False)
        self.object.user = self.request.user
        self.object.save()
        success_message('Rule "{}" created successfully.'.format(
                        self.object), self.request)
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return reverse('core:user_alert_rule-list')


class UserAlertRuleEditView(PermissionRequiredMixin, UpdateView):
    permission_required = {
        'get': 'core.view_useralertrule',
        'post': 'core.change_useralertrule'
    }
    pk_url_kwarg = 'pk'
    form_class = UserAlertRuleForm
    model = UserAlertRule
    template_name = 'network_monitor/core/user_alert_rule/edit.html'

    def get_context_data(self, **kwargs):
        ctx = super(UserAlertRuleEditView, self).get_context_data(**kwargs)
        ctx.update(user_alert_rule_contxt())
        return ctx

    def get_queryset(self):
        return UserAlertRule.objects.filter(user=self.request.user)

    def form_valid(self, form):
        result = super(UserAlertRuleEditView, self).form_valid(form)
        success_message('Rule "{}" updated successfully.'.format(
                        self.object), self.request)
        return result

    def get_success_url(self):
        return reverse('core:user_alert_rule-list')


class UserAlertRuleDeleteView(PermissionRequiredMixin, SingleObjectMixin,
                              View):
    permission_required = 'core.delete_useralertrule'
    pk_url_kwarg = 'pk'
    model = UserAlertRule

    def get_queryset(self):
        return UserAlertRule.objects.filter(user=self.request.user)

    def post(self, request, *args, **kwargs):
        user_alert_rule = self.get_object()
        user_alert_rule.delete()
        success_message(
            'Rule "{}" deleted successfully!'.format(user_alert_rule),
            self.request)
        return redirect(reverse('core:user_alert_rule-list'))


class DeviceFeatureObjectMixin(object):
    device_id_url_kwarg = 'device_id'
    feature_url_kwarg = 'feature'
    device_feature_object = None
    device_object = None

    def get_device_feature(self):
        if not self.device_feature_object:
            device_id = self.kwargs.get(self.device_id_url_kwarg)
            try:
                self.device_object = Device.objects.get(pk=device_id)
            except Device.DoesNotExist:
                raise Http404(
                    'Device with id {} does not exists'.format(device_id))
            feature = self.kwargs.get(self.feature_url_kwarg, None)
            all_features = [f[0] for f in DeviceFeature.FEATURE_CHOICES]
            if feature not in all_features:
                raise Http404(
                    'feature {} does not exists'.format(feature))
            self.device_feature_object, created = \
                self.device_object.feature.get_or_create(feature=feature)
        return self.device_feature_object

    def get_mon_config(self):
        app_feature = self.get_device_feature().app_feature
        return getattr(app_feature, 'mon_config', {})

    def dispatch(self, request, *args, **kwargs):
        self.get_device_feature()
        return super(DeviceFeatureObjectMixin, self
                     ).dispatch(request, *args, **kwargs)


class DeviceFeatureConfigView(PermissionRequiredMixin,
                              DeviceFeatureObjectMixin, UpdateView):
    permission_required = {
        'get': 'core.view_devicefeature',
        'post': 'core.change_devicefeature'
    }
    form_class = DeviceFeatureForm
    model = DeviceFeature
    template_name = 'network_monitor/core/device_feature/config.html'

    def get_object(self):
        return self.get_device_feature()

    def form_valid(self, form):
        result = super(DeviceFeatureConfigView, self).form_valid(form)
        success_message(
            '"{}" config of device "{}" updated successfully.'.format(
                self.device_feature_object.feature, self.device_object),
            self.request)
        return result

    def form_invalid(self, form):
        result = super(DeviceFeatureConfigView, self).form_invalid(form)
        return result

    def get_success_url(self):
        return reverse('core:device-features', args=(self.device_object.pk,))


class DeviceFeatureChartsView(PermissionRequiredMixin,
                              DeviceFeatureObjectMixin, TemplateView):
    permission_required = 'core.view_devicefeature'
    template_name = 'network_monitor/core/device_feature/charts.html'

    def get_chart_data(self):
        return {}

    def get_report_data(self):
        return {}

    def get_context_data(self, **kwargs):
        ctx = super(DeviceFeatureChartsView, self).get_context_data(**kwargs)
        ctx['device_feature'] = self.get_device_feature()
        ctx['chart_data'] = self.get_chart_data()
        ctx['report_data'] = self.get_report_data()
        return ctx


class DeviceFeatureThresholdListView(PermissionRequiredMixin,
                                     DeviceFeatureObjectMixin, TemplateView):
    permission_required = 'core.view_threshold'
    template_name = 'network_monitor/core/device_feature/threshold/list.html'

    def get_threshold_config(self):
        mon_config = self.get_mon_config()
        return mon_config.get('threshold', {}).get('types', {}).\
            get(self.threshold_type, {})

    def get_avail_threshold_types(self):
        mon_config = self.get_mon_config()
        return list(mon_config.get('threshold', {}).get('types', {}).keys())

    def get_context_data(self, **kwargs):
        ctx = super(DeviceFeatureThresholdListView, self
                    ).get_context_data(**kwargs)
        device_feature = self.get_device_feature()
        ctx['device_feature'] = device_feature
        ctx['thresholds'] = device_feature.threshold.order_by('id').all()
        ctx['avail_threshold_types'] = self.get_avail_threshold_types()
        return ctx


class DeviceFeatureThresholdAddView(PermissionRequiredMixin,
                                    DeviceFeatureObjectMixin, CreateView):
    permission_required = 'core.add_device'
    form_class = ThresholdForm
    template_name = 'network_monitor/core/device_feature/threshold/add.html'
    threshold_type_url_kwarg = 'threshold_type'

    def get_threshold_config(self):
        mon_config = self.get_mon_config()
        return mon_config.get('threshold', {}).get('types', {}).\
            get(self.threshold_type, {})

    def get_avail_threshold_types(self):
        mon_config = self.get_mon_config()
        return list(mon_config.get('threshold', {}).get('types', {}).keys())

    def get_template_names(self):
        templates = super(DeviceFeatureThresholdAddView, self
                          ).get_template_names()
        templates.insert(0, 'network_monitor/core/device_feature/threshold/{}-add.html'.format(
            self.threshold_type))
        return templates

    def check_threshold_type(self, kwargs):
        threshold_type = self.kwargs.get(self.threshold_type_url_kwarg)
        if threshold_type not in self.get_avail_threshold_types():
            raise Http404(
                'Threshold {} does not exists'.format(threshold_type))
        self.threshold_type = threshold_type

    def get(self, request, *args, **kwargs):
        self.check_threshold_type(kwargs)
        return super(DeviceFeatureThresholdAddView, self).get(request, *args,
                                                              **kwargs)

    def post(self, request, *args, **kwargs):
        self.check_threshold_type(kwargs)
        return super(DeviceFeatureThresholdAddView, self).post(request, *args,
                                                               **kwargs)

    def get_context_data(self, **kwargs):

        ctx = super(DeviceFeatureThresholdAddView, self
                    ).get_context_data(**kwargs)
        device_feature = self.get_device_feature()
        ctx['device_feature'] = device_feature
        ctx['threshold_type'] = self.threshold_type
        ctx['threshold_config'] = self.get_threshold_config()
        return ctx

    def form_valid(self, form):
        self.object = form.save(commit=False)
        self.object.type = self.threshold_type
        self.object.device_feature = self.device_feature_object
        self.object.save()

        success_message('Threshold "{}" created successfully.'.format(
                        self.object), self.request)
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        df = self.get_device_feature()
        return reverse('device-feature-threshold-list',
                       args=(self.device_object.pk, df.feature))


class DeviceFeatureThresholdDeleteView(PermissionRequiredMixin,
                                       DeviceFeatureObjectMixin,
                                       SingleObjectMixin, View):
    permission_required = 'core.delete_threshold'
    pk_url_kwarg = 'threshold_id'
    model = Threshold

    def get_queryset(self):
        return self.get_device_feature().threshold

    def post(self, request, *args, **kwargs):
        threshold = self.get_object()
        threshold.delete()
        success_message(
            'Threshold "{}" deleted successfully!'.format(threshold),
            self.request)
        return redirect(self.get_success_url())

    def get_success_url(self):
        df = self.get_device_feature()
        return reverse('device-feature-threshold-list',
                       args=(self.device_object.pk, df.feature))


class DeviceFeatureThresholdSwitchView(PermissionRequiredMixin,
                                       DeviceFeatureObjectMixin,
                                       SingleObjectMixin, View):
    permission_required = 'core.change_threshold'
    pk_url_kwarg = 'threshold_id'
    model = Threshold

    def get_queryset(self):
        return self.get_device_feature().threshold

    def post(self, request, *args, **kwargs):
        threshold = self.get_object()
        threshold.active = not threshold.active
        threshold.save()
        status = 'Enabled' if threshold.active else 'Disabled'
        success_message(
            'Threshold "{}" {} successfully!'.format(threshold, status),
            self.request)
        return redirect(self.get_success_url())

    def get_success_url(self):
        df = self.get_device_feature()
        return reverse('device-feature-threshold-list',
                       args=(self.device_object.pk, df.feature))


class SettingGeneralView(PermissionRequiredMixin, View):
    permission_required = 'dynamic_preferences.change_globalpreferencemodel'
    template_name = "network_monitor/core/settings/general.html"
    sections = ['dhcp_scan']

    def get_form(self, section=None):
        data = None
        if self.request.method == 'POST':
            data = self.request.POST
        form_class = global_preference_form_builder(**({'section': section} if section else {}))
        return form_class(data=data)

    def get_context(self):
        forms = {section: self.get_form(section=section) for section in self.sections}
        return {'forms': forms}

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, self.get_context())

    def post(self, request, *args, **kwargs):

        form = self.get_form()
        if form.is_valid():
            global_preferences = global_preferences_registry.manager()
            for k, v in form.cleaned_data.items():
                global_preferences[k] = v

            success_message('Settings Updated successfully', request)
            return redirect('core:settings-general')

        return render(request, self.template_name, self.get_context())
