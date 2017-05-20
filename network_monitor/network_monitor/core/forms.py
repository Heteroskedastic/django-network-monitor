from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import password_validation
from django.forms.widgets import PasswordInput, TextInput, CheckboxInput
from django import forms
from ckeditor.widgets import CKEditorWidget
from phonenumber_field.formfields import PhoneNumberField

from .models import Device, DeviceFeature, Threshold, UserAlertRule, \
    MEDIA_CHOICES


boolean_toggle_attrs = {
    'data-onstyle': 'success', 'data-offstyle': 'danger', 'data-toggle': 'toggle', 'data-on': 'Enabled',
    'data-off': 'Disabled', 'data-width': '90px',
}


class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=TextInput(
        attrs={'class': 'form-control', 'placeholder': 'Username',
               'required': True}))
    password = forms.CharField(widget=PasswordInput(
        attrs={'class': 'form-control', 'placeholder': 'Password',
               'required': True}))


class RegistrationForm(forms.ModelForm):
    """
    new user register
    """
    email = forms.EmailField(label='Email', required=True)
    password = forms.CharField(label='Password', widget=forms.PasswordInput,
                               required=True)
    password2 = forms.CharField(widget=forms.PasswordInput,
                                required=True,
                                label="Confirm password ")

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password',
                  'password2']

    def __init__(self, *args, **kwargs):
        # from django.forms.widgets import HiddenInput
        super(RegistrationForm, self).__init__(*args, **kwargs)
        for filed in self.fields:
            field_label = self.fields[filed].label
            if self.fields[filed].required and field_label:
                self.fields[filed].widget.attrs.update({
                    'placeholder': field_label,
                })
                self.fields[filed].label = field_label + " (*)"

    def clean_password2(self):
        password1 = self.cleaned_data["password"]
        password2 = self.cleaned_data["password2"]
        if password1 == '' or password2 == '':
            raise forms.ValidationError("You must enter password")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        password_validation.validate_password(
            self.cleaned_data.get('password2'), self.instance)
        return password2

    def clean_email(self):
        data = self.cleaned_data['email']
        if User.objects.filter(email=data).exists():
            raise forms.ValidationError("This email already used")
        return data


class ProfileForm(forms.ModelForm):
    """
    User profile
    """
    sms_number = PhoneNumberField(required=False)

    class Meta:
        model = User
        _profile_fields = ['sms_number']
        fields = ['first_name', 'last_name', 'email', ] + _profile_fields

    def save(self, *args, **kwargs):
        profile = self.instance.profile
        for field in self.Meta._profile_fields:
            val = self.cleaned_data.get(field)
            setattr(profile, field, val)
        res = super(ProfileForm, self).save(*args, **kwargs)
        return res


class DeviceForm(forms.ModelForm):

    class Meta:
        model = Device
        exclude = ['status', 'last_seen', 'mac_manufacture']
        widgets = {
            'tags': TextInput(attrs={'data-role': 'tagsinput', 'width': '100%'}),
            'active': CheckboxInput(attrs=boolean_toggle_attrs)
        }
        labels = {
            'active': ''
        }


class DeviceFeatureForm(forms.ModelForm):

    def clean(self):
        args = self.cleaned_data.get('args')
        if not args:
            self.cleaned_data['args'] = {}
        conf = self.cleaned_data.get('conf')
        if not conf:
            self.cleaned_data['conf'] = {}
        return self.cleaned_data

    class Meta:
        model = DeviceFeature
        fields = ['round_interval', 'active', 'args', 'conf']
        widgets = {
            'active': CheckboxInput(attrs=boolean_toggle_attrs)
        }
        labels = {
            'active': ''
        }


class ThresholdForm(forms.ModelForm):

    class Meta:
        model = Threshold
        fields = ['name', 'severity', 'active', 'data']
        widgets = {
            'active': CheckboxInput(attrs=boolean_toggle_attrs)
        }
        labels = {
            'active': ''
        }


class UserAlertRuleForm(forms.ModelForm):
    notify_media = forms.TypedMultipleChoiceField(
        label='Notify via',
        widget=forms.CheckboxSelectMultiple(attrs={'max-height': '100px'}),
        choices=MEDIA_CHOICES, required=True)
    custom_message = forms.CharField(widget=CKEditorWidget(config_name='awesome'), required=False)
    class Meta:
        model = UserAlertRule
        fields = ['active', 'name', 'notify_media', 'rules', 'custom_message']
        widgets = {
            'active': CheckboxInput(attrs=boolean_toggle_attrs)
        }
        labels = {
            'active': ''
        }
