# ROOT 19

A web-based quiz application built with Django that allows users to register, log in, practice questions, and track progress. This project features a dynamic and user-friendly interface, including a hero section, session-based authentication, and animated feedback.

This version uses **Supabase (PostgreSQL)** for data storage instead of MongoDB. All data is stored in PostgreSQL tables and accessed with `psycopg2`.

## Features

- **User Authentication**:
  - Registration with email, password, and user role (Student/Teacher).
  - Login and Logout functionality.
  - Navbar displays "Welcome, User" when logged in.
  
- **Question Management**:
  - Practice questions by selecting session codes and subtopics.
  - Dynamic loading of subtopics based on the selected session code.
  - Feedback for correct/incorrect answers.
  
- **Home Page**:
  - Animated hero section.
  - Real-time display of the total number of questions in the database.

## Tracking User Activity

The `user_activity` table stores per-question data linked by `user_id` and
`question_id`. It records whether questions are starred or bookmarked, if they
have been solved correctly and how long the user spent on each. Superusers can
view these records at `/admin/user-activity/`.

## Password Security

User passwords are **never stored in plain text**. During registration the
application hashes the password using Django's PBKDF2 implementation with a
unique salt for each user. At login the hash is verified using the same
algorithm. Storing hashes instead of raw passwords helps protect user
credentials even if the database is compromised.

## Prerequisites

Make sure you have the following installed:

- Python 3.x
- Django 4.x
- PostgreSQL server (Supabase)
- psycopg2-binary

## Question Image Storage (CDN)

Question images can be delivered from Supabase Storage instead of inline Base64.

Set these environment variables:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_STORAGE_BUCKET`
- `SUPABASE_STORAGE_PUBLIC_BASE_URL` (optional override)

Backfill existing question images:

```bash
python manage.py backfill_question_images --dry-run
python manage.py backfill_question_images
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/quiz-app.git
   cd quiz-app
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run migrations:
   ```bash
   python manage.py migrate
   ```

4. Start server:
   ```bash
   python manage.py runserver
   ```

## API Documentation

For API usage, authentication, filters, and subject options, see:

- `docs/API_DOCUMENTATION.md`
