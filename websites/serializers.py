class WebsiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Website
        fields = ['id', 'name', 'description', 'version', 'icon', 
                 'is_installed', 'installed_at'] 