from django import forms
from .models import Website, AdditionalDomain

class WebsiteForm(forms.ModelForm):
    SSL_PROVIDERS = (
        ('none', '不使用 SSL'),
        ('cloudflare', 'Cloudflare'),
        ('letsencrypt', "Let's Encrypt"),
    )
    
    ssl_provider = forms.ChoiceField(
        choices=SSL_PROVIDERS,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'}),
        label='SSL 提供商'
    )
    
    class Meta:
        model = Website
        fields = ['name', 'domain', 'server_type', 'php_version', 'ssl_provider']
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
