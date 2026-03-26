from django.contrib import admin
from .models import Machine, Alert, DetectionRule

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('alert_type', 'severity', 'machine', 'created_at')
    list_filter = ('severity', 'machine')
    search_fields = ('alert_type', 'description')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'

admin.site.register(Machine)
admin.site.register(DetectionRule)
