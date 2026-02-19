from django.contrib import admin
from django.contrib import messages
from django.utils.html import format_html
from .models import BugReport, APIKey


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


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "access_mode",
        "usage_count",
        "request_limit",
        "key_prefix",
        "is_active",
        "created_at",
        "expires_at",
        "last_used_at",
    )
    list_display_links = ("id", "name")
    list_filter = ("is_active", "created_at", "expires_at")
    search_fields = ("name", "key_prefix")
    readonly_fields = ("key_prefix", "key_hash", "usage_count", "created_at", "last_used_at")
    actions = ("regenerate_api_keys",)

    fieldsets = (
        (None, {
            "fields": ("name", "access_mode", "request_limit", "is_active", "expires_at", "notes")
        }),
        ("Stored Fingerprint", {
            "fields": ("key_prefix", "key_hash", "usage_count", "created_at", "last_used_at")
        }),
    )

    @admin.action(description="Regenerate selected API key(s)")
    def regenerate_api_keys(self, request, queryset):
        if not queryset:
            self.message_user(request, "No API key selected.", level=messages.WARNING)
            return

        generated = []
        for api_key in queryset:
            raw_key = APIKey.generate_raw_key()
            api_key.set_raw_key(raw_key)
            api_key.save(update_fields=["key_hash", "key_prefix"])
            generated.append((api_key.name or str(api_key.id), raw_key))

        for label, raw in generated:
            self.message_user(
                request,
                f"Regenerated key for '{label}'. Copy now (shown once): {raw}",
                level=messages.WARNING,
            )

    def save_model(self, request, obj, form, change):
        raw_key = None
        if not obj.key_hash:
            raw_key = APIKey.generate_raw_key()
            obj.set_raw_key(raw_key)

        super().save_model(request, obj, form, change)

        if raw_key:
            self.message_user(
                request,
                f"API key generated for '{obj.name or obj.id}'. Copy now (shown once): {raw_key}",
                level=messages.WARNING,
            )

# Simple customization of the default Django admin site
admin.site.site_header = "Quiz Administration"
admin.site.site_title = "Quiz Admin"
admin.site.index_title = "Site Overview"
