# Security Best Practices Report

## Executive Summary

This review covered the Django backend and the browser-side JavaScript used by the application. The most important issues are a broken access control flaw in `/update-activity/`, multiple session-authenticated POST endpoints with CSRF protection explicitly disabled, and committed secret-bearing defaults in server settings. Together, these issues could let an attacker tamper with user data, perform unwanted actions from a victim's browser, or gain access to backend infrastructure if the committed credentials are live.

## Critical / High

### F-001
- Rule ID: DJANGO-CONFIG-001
- Severity: High
- Location: `root_19/settings.py` lines 23, 91-129
- Evidence:

```python
SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-change-this-to-a-unique-key")
DB_HOST = os.getenv("DB_HOST", "aws-1-ap-south-1.pooler.supabase.com")
DB_USER = os.getenv("DB_USER", "postgres.vzmbwobdlddxzgqfhnsh")
DB_PASSWORD = os.getenv("DB_PASSWORD", "[REDACTED HARDCODED VALUE]")
DATABASE_URL = os.getenv(
    "DATABASE_URL", f"postgresql://{DB_USER}:[REDACTED]@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
```

- Impact: If these defaults are active or reused anywhere, anyone with source access can connect to the database or reuse the credentials elsewhere.
- Fix: Remove all secret-bearing defaults from code, require them from environment or a secret manager, and rotate the database credentials immediately. Treat `SECRET_KEY` as required in non-dev environments instead of falling back to a static string.
- Mitigation: Ensure `.env` is ignored, store secrets in deployment configuration only, and add a startup check that fails closed when required secrets are missing.
- False positive notes: I did not test whether the embedded database credentials are currently valid, but they are formatted like real service credentials rather than safe placeholders.

### F-002
- Rule ID: DJANGO-AUTHZ-001
- Severity: High
- Location: `main/views.py` lines 2342-2418, `main/db.py` lines 95-101, `main/templates/practice_questions.html` lines 247-248 and 341-345, `main/templates/saved_questions.html` lines 187 and 208-212, `main/templates/duel_detail.html` lines 135 and 291-298
- Evidence:

```python
@csrf_exempt
@require_POST
def update_activity(request):
    data = json.loads(request.body.decode("utf-8"))
    user_id = data.get("user_id")
    ...
    user = query_one("SELECT * FROM users WHERE user_id = %s", (user_id,))
```

```python
def get_next_user_id() -> str:
    row = query_one(
        "SELECT COALESCE(MAX(CAST(SUBSTRING(user_id FROM 2) AS INTEGER)), 0) AS max_num FROM users"
    )
    return f"U{max_num + 1}"
```

```javascript
const USER_ID = "{{ user_id|default:'' }}";
body: JSON.stringify({ user_id: USER_ID, ...payload })
```

- Impact: Any attacker can submit activity updates for any user by choosing a `user_id`; because IDs are sequential (`U1`, `U2`, ...), this is practical to exploit at scale and can corrupt bookmarks, stars, answer status, and progress data.
- Fix: Ignore `user_id` from the request body and derive the acting user exclusively from `request.session["user_id"]`. Reject unauthenticated requests before touching any activity rows.
- Mitigation: Rate-limit the endpoint and audit recent activity data for cross-user tampering if the app has been publicly reachable.
- False positive notes: This finding does not depend on CSRF. The endpoint accepts unauthenticated requests and trusts caller-supplied identity directly.

### F-003
- Rule ID: DJANGO-CSRF-001
- Severity: High
- Location: `main/views.py` lines 2089-2148, 2151-2246, 2266-2340, 3426-3534; `main/templates/chat.html` lines 282-286; `main/templates/practice_questions.html` lines 727-734 and 764-772
- Evidence:

```python
@csrf_exempt
@require_POST
def report_question(request):
```

```python
@csrf_exempt
@require_POST
def api_create_duel(request):
```

```python
@csrf_exempt
@require_POST
def api_join_duel(request):
```

```python
@csrf_exempt
@require_POST
def api_duel_submit(request, duel_id: int):
```

```python
@csrf_exempt
@require_POST
def chat_share_question(request):
```

```python
@csrf_exempt
@require_POST
def chat_ping(request):
```

```javascript
fetch("/chat/ping/", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(payload),
})
```

- Impact: A malicious site can cause a logged-in victim's browser to create/join duels, submit duel answers, create question reports, send chat pings, or mark chat notifications as read by replaying the victim's session cookie.
- Fix: Remove `@csrf_exempt` from session-authenticated views and require a CSRF token for every state-changing request. For JavaScript clients, send `X-CSRFToken` using the standard Django cookie/token pattern.
- Mitigation: If an endpoint truly must be cross-origin, move it to token-based auth instead of session-cookie auth and validate `Origin` explicitly.
- False positive notes: `check_answer` is also CSRF-exempt, but it is read-only; the higher-risk issue is the set of state-changing endpoints above.

## Medium

### F-004
- Rule ID: DJANGO-SECRETS-TRANSPORT-001
- Severity: Medium
- Location: `main/views.py` lines 1656-1666; `main/views.py` lines 986-988
- Evidence:

```python
key_from_query = (
    request.GET.get("api_key")
    or request.GET.get("apikey")
    or request.GET.get("key")
    or ""
).strip()
```

```python
{"name": "api_key", "description": "API key in URL (fallback when header control is not available)."}
```

- Impact: API keys passed in URLs are exposed to browser history, server logs, analytics systems, screenshots, and sometimes `Referer` headers to third parties.
- Fix: Accept API keys only in headers such as `Authorization: Bearer ...` or `X-API-Key`. Remove query-string support from both code and documentation.
- Mitigation: If query-string support must remain briefly for compatibility, disable it by default and warn clients that it is deprecated and unsafe.
- False positive notes: This does not prove active leakage today, but accepting credentials in URLs is a well-known secret-handling anti-pattern.

### F-005
- Rule ID: DJANGO-AUTH-002
- Severity: Medium
- Location: `root_19/settings.py` lines 140-151; `main/views.py` lines 137-159, 246-264, 2967-2983
- Evidence:

```python
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
```

```python
hashed_password = make_password(password)
...
hashed = make_password(new_password)
...
execute(
    "UPDATE users SET password = %s WHERE user_id = %s",
    (make_password(new_password), target_id),
)
```

- Impact: Users and staff can set weak or highly guessable passwords even though password validators are configured, which increases credential-stuffing and account-takeover risk.
- Fix: Run `django.contrib.auth.password_validation.validate_password(...)` before hashing new passwords in registration, self-service password change, and staff reset flows.
- Mitigation: Add login throttling and monitoring for failed attempts while password policy is being fixed.
- False positive notes: The configured validators only apply when they are called. This code path bypasses Django's normal auth forms, so the validators are not currently enforced.

## Additional Verification Recommended

These items were not strong enough for a primary finding because the effective protection might be added outside the repo, but they should still be checked before production sign-off.

### V-001
- Observation: `root_19/settings.py` does not define `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_SSL_REDIRECT`, `SECURE_PROXY_SSL_HEADER`, `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_REFERRER_POLICY`, or a CSP setting.
- Why it matters: For an HTTPS login-capable Django app, secure cookie flags and header hardening are part of the normal production baseline. If these are not enforced at the edge, session transport and browser isolation are weaker than they should be.
- What to verify: Confirm whether these controls are set by deployment infrastructure. If not, add them in Django settings with environment-aware toggles so local HTTP development still works.

### V-002
- Observation: Many templates load third-party assets from CDNs and external origins, including `cdn.jsdelivr.net`, `code.jquery.com`, Google Fonts, and `datafa.st` analytics, without any visible Subresource Integrity or in-repo CSP policy.
- Why it matters: Third-party JavaScript runs with first-party origin privileges. Without CSP/SRI, compromise or tampering of a dependency host has a larger blast radius.
- What to verify: Prefer first-party hosting or add SRI where possible, and deploy a CSP at the HTTP header layer.

## Suggested Fix Order

1. Fix `/update-activity/` so it uses session identity only.
2. Re-enable CSRF protection on all session-authenticated POST endpoints and update the frontend fetch calls.
3. Rotate database credentials and remove all hard-coded secret defaults from code.
4. Remove API key query-string support.
5. Enforce password validation in every password-setting flow.
