#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from pathlib import Path


def _load_dotenv():
    """Load variables from .env file into os.environ."""
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path, override=False)
        return
    except ImportError:
        pass
    # Fallback: simple parser if python-dotenv not installed
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def main():
    """Run administrative tasks."""
    _load_dotenv()
    print("[manage.py] Starting Django management utility...")
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'root_19.settings')
    print(f"[manage.py] DJANGO_SETTINGS_MODULE={os.environ.get('DJANGO_SETTINGS_MODULE')}")
    try:
        print("[manage.py] Importing execute_from_command_line...")
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        print("[manage.py] Failed to import Django; ensure the environment is set up.")
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    print(f"[manage.py] Running command with args: {sys.argv}")
    execute_from_command_line(sys.argv)
    print("[manage.py] Command completed.")


if __name__ == '__main__':
    main()
