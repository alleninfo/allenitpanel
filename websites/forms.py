from django import forms
from .models import Website, AdditionalDomain

class WebsiteForm(forms.ModelForm):
    class Meta:
        model = Website
        fields = ['name', 'domain', 'server_type', 'php_version']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'domain': forms.TextInput(attrs={'class': 'form-control'}),
            'server_type': forms.Select(attrs={'class': 'form-control'}),
            'php_version': forms.Select(attrs={'class': 'form-control'}),
        }

class AdditionalDomainForm(forms.ModelForm):
    class Meta:
        model = AdditionalDomain
        fields = ['domain']
        widgets = {
            'domain': forms.TextInput(attrs={'class': 'form-control'}),
        }
