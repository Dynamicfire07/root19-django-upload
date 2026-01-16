FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps for psycopg2-binary and gzip
RUN apt-get update \ 
    && apt-get install -y --no-install-recommends gcc libpq-dev \ 
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY manage.py /app/
COPY root_19 /app/root_19
COPY main /app/main

EXPOSE 8000

CMD ["gunicorn", "root_19.wsgi:application", "--bind", "0.0.0.0:8000"]
