"""Django settings for myproject project."""

from pathlib import Path
import os

try:
    import whitenoise  # noqa: F401
    WHITENOISE_AVAILABLE = True
except ImportError:
    WHITENOISE_AVAILABLE = False

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Security / environment toggles
SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-change-this-to-a-unique-key")
DEBUG = os.getenv("DEBUG", "False").lower() in {"1", "true", "yes"}

_default_hosts = "app.root19.com,34.14.174.152,127.0.0.1,localhost"
ALLOWED_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HOSTS", _default_hosts).split(",") if h.strip()]

CSRF_TRUSTED_ORIGINS = [
    "http://app.root19.com",
    "https://app.root19.com"
]

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'root_19',
    'main'

]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.gzip.GZipMiddleware',
]
if WHITENOISE_AVAILABLE:
    # Serve compressed static assets efficiently in production.
    MIDDLEWARE.append('whitenoise.middleware.WhiteNoiseMiddleware')

MIDDLEWARE += [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'main.middleware.StaticMediaCacheMiddleware',
]

ROOT_URLCONF = 'root_19.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        # You can add your template directories inside the list below
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'root_19.wsgi.application'


# Database
# Configure PostgreSQL via environment variables with sensible defaults (Supabase values).
DB_HOST = os.getenv("DB_HOST", "aws-1-ap-south-1.pooler.supabase.com")
DB_PORT = os.getenv("DB_PORT", "6543")
DB_NAME = os.getenv("DB_NAME", "postgres")
DB_USER = os.getenv("DB_USER", "postgres.vzmbwobdlddxzgqfhnsh")
DB_PASSWORD = os.getenv("DB_PASSWORD", "shaishavroot19")
DB_SSLMODE = os.getenv("DB_SSLMODE", "require")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": DB_NAME,
        "USER": DB_USER,
        "PASSWORD": DB_PASSWORD,
        "HOST": DB_HOST,
        "PORT": DB_PORT,
        "OPTIONS": {"sslmode": DB_SSLMODE},
    }
}
# Optional: separate chat database (e.g., Cloud SQL) while keeping questions on Supabase.
CHAT_DB_HOST = os.getenv("CHAT_DB_HOST", DB_HOST)
CHAT_DB_PORT = os.getenv("CHAT_DB_PORT", DB_PORT)
CHAT_DB_NAME = os.getenv("CHAT_DB_NAME", DB_NAME)
CHAT_DB_USER = os.getenv("CHAT_DB_USER", DB_USER)
CHAT_DB_PASSWORD = os.getenv("CHAT_DB_PASSWORD", DB_PASSWORD)
CHAT_DB_SSLMODE = os.getenv("CHAT_DB_SSLMODE", DB_SSLMODE)
CHAT_DB = {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": CHAT_DB_NAME,
    "USER": CHAT_DB_USER,
    "PASSWORD": CHAT_DB_PASSWORD,
    "HOST": CHAT_DB_HOST,
    "PORT": CHAT_DB_PORT,
    "OPTIONS": {"sslmode": CHAT_DB_SSLMODE},
}
# Seconds to wait when opening the DB connection (used by main/db.py).
DB_CONNECT_TIMEOUT = int(os.getenv("DB_CONNECT_TIMEOUT", "5"))
DATABASE_URL = os.getenv(
    "DATABASE_URL", f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

# Supabase Storage (questions images)
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
SUPABASE_STORAGE_BUCKET = os.getenv("SUPABASE_STORAGE_BUCKET", "")
SUPABASE_STORAGE_PUBLIC_BASE_URL = os.getenv("SUPABASE_STORAGE_PUBLIC_BASE_URL", "").rstrip("/")

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

# In Django 4.0+, USE_L10N was deprecated; you can omit or leave it if you’re on older Django
# USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/
# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
# --- Deployment: static & media ---
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'main' / 'static',
]

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# (already set elsewhere—keep as you have)

# Sessions: keep users signed in longer by default
SESSION_COOKIE_AGE = 60 * 60 * 24 * 30  # 30 days
SESSION_SAVE_EVERY_REQUEST = True  # refresh expiry on activity
if WHITENOISE_AVAILABLE:
    # Use compressed storage without manifest requirement to avoid missing-file errors in dev.
    STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'
else:
    STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'
    
