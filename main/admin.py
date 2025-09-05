from django.contrib import admin
from django.utils.html import format_html
from .models import BugReport


@admin.register(BugReport)
class BugReportAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "severity", "status", "created_at")
    list_display_links = ("id", "title")
    list_filter = ("severity", "status", "created_at")
    search_fields = ("title", "description", "contact_email")
    readonly_fields = ("created_at", "updated_at", "screenshot_preview")

    fieldsets = (
        (None, {
            "fields": ("title", "description", "steps_to_reproduce")
        }),
        ("Details", {
            "fields": ("severity", "status", "contact_email")
        }),
        ("Screenshot", {
            "fields": ("screenshot", "screenshot_preview")
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at")
        }),
    )

    def screenshot_preview(self, obj):
        if obj.screenshot:
            return format_html('<img src="{}" style="max-height:200px;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,.08)" />', obj.screenshot.url)
        return "—"
    screenshot_preview.short_description = "Preview"

# Simple customization of the default Django admin site
admin.site.site_header = "Quiz Administration"
admin.site.site_title = "Quiz Admin"
admin.site.index_title = "Site Overview"
