from django.db import models
import hashlib
import secrets


class Question(models.Model):
    question_id = models.CharField(max_length=255, primary_key=True)
    session_code = models.CharField(max_length=100)
    session = models.CharField(max_length=100)
    year = models.IntegerField()
    paper_code = models.CharField(max_length=50)
    variant = models.CharField(max_length=50)
    file_question = models.TextField()
    subtopic = models.CharField(max_length=255)
    extracted_text = models.TextField()
    image_base64 = models.TextField()
    image_key = models.TextField(blank=True, null=True)
    image_url = models.TextField(blank=True, null=True)
    answer = models.TextField()

    class Meta:
        db_table = "questions"   



class User(models.Model):
    user_id = models.CharField(max_length=255, primary_key=True)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)  # store hashes, not plaintext
    role = models.CharField(max_length=50)
    school = models.CharField(max_length=255)
    champion_theme_access = models.BooleanField(default=False)
    
    class Meta:
        db_table = "users"


class UserActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    solved = models.BooleanField(default=False)
    correct = models.BooleanField(default=False)
    bookmarked = models.BooleanField(default=False)
    starred = models.BooleanField(default=False)
    times_viewed = models.IntegerField(default=0)
    time_started = models.DateTimeField(null=True, blank=True)
    time_took = models.DurationField(null=True, blank=True)

    class Meta:
        db_table = "user_activity"


class BugReport(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    steps_to_reproduce = models.TextField(blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default="medium")
    contact_email = models.EmailField(blank=True)
    screenshot = models.ImageField(upload_to="bug_screenshots/", blank=True, null=True)
    status = models.CharField(max_length=20, default="open")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "bug_reports"

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"


class APIKey(models.Model):
    ACCESS_MODE_UNLIMITED = "unlimited"
    ACCESS_MODE_LIMITED = "limited"
    ACCESS_MODE_CHOICES = [
        (ACCESS_MODE_UNLIMITED, "Unlimited"),
        (ACCESS_MODE_LIMITED, "Limited"),
    ]

    name = models.CharField(max_length=120)
    key_prefix = models.CharField(max_length=16, db_index=True, editable=False)
    key_hash = models.CharField(max_length=64, unique=True, editable=False)
    access_mode = models.CharField(max_length=20, choices=ACCESS_MODE_CHOICES, default=ACCESS_MODE_UNLIMITED)
    request_limit = models.PositiveIntegerField(blank=True, null=True)
    usage_count = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(blank=True, null=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    notes = models.TextField(blank=True)

    class Meta:
        db_table = "api_keys"
        ordering = ("-created_at",)

    def __str__(self):
        label = self.name or self.key_prefix
        status = "active" if self.is_active else "inactive"
        return f"{label} ({status})"

    @staticmethod
    def generate_raw_key() -> str:
        return f"r19_{secrets.token_urlsafe(32)}"

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def set_raw_key(self, raw_key: str) -> None:
        normalized = (raw_key or "").strip()
        if not normalized:
            raise ValueError("API key cannot be empty.")
        self.key_hash = self.hash_key(normalized)
        self.key_prefix = normalized[:16]
