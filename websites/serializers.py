from rest_framework import serializers
from .models import Website

class WebsiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Website
        fields = ['id', 'name', 'description', 'version', 'icon', 
                 'is_installed', 'installed_at'] 