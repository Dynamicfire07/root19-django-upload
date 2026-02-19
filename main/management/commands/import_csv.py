import csv
import sys
from django.core.management.base import BaseCommand
from main.db import execute
from main.question_images import ensure_question_image_columns
from main.supabase_storage import (
    is_supabase_storage_configured,
    upload_question_base64,
    StorageUploadError,
)

csv.field_size_limit(sys.maxsize)

class Command(BaseCommand):
    help = 'Import questions from a CSV file into PostgreSQL'

    def add_arguments(self, parser):
        parser.add_argument(
            '--path',
            type=str,
            default='/Users/shauryajain/Downloads/root_19/compelted.csv',
            help='Path to the CSV file to import'
        )

    def handle(self, *args, **options):
        csv_path = options['path']
        self.stdout.write(self.style.WARNING(f"Starting import from: {csv_path}"))
        ensure_question_image_columns()
        storage_enabled = is_supabase_storage_configured()
        if storage_enabled:
            self.stdout.write(self.style.WARNING("Supabase storage is configured; question images will be uploaded."))
        else:
            self.stdout.write(self.style.WARNING("Supabase storage not configured; keeping Base64 only."))

        try:
            with open(csv_path, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                imported_count = 0
                for row in reader:
                    try:
                        # Validate required fields
                        question_id = row.get('QuestionID')
                        if not question_id:
                            raise ValueError('Missing QuestionID')

                        # Clean and convert fields
                        year_str = row.get('Year')
                        year = int(year_str) if year_str and year_str.isdigit() else None
                        image_base64 = row.get('ImageBase64', '').strip()
                        image_key = None
                        image_url = None
                        if image_base64 and storage_enabled:
                            try:
                                uploaded = upload_question_base64(question_id, image_base64)
                                image_key = uploaded.get("image_key")
                                image_url = uploaded.get("image_url")
                            except StorageUploadError as upload_error:
                                self.stderr.write(
                                    self.style.ERROR(
                                        f"Upload failed for QuestionID {question_id}; keeping Base64 only: {upload_error}"
                                    )
                                )

                        execute(
                            """
                            INSERT INTO questions (
                                question_id, session_code, session, year,
                                paper_code, variant, file_question, subtopic,
                                extracted_text, image_base64, image_key, image_url, answer
                            ) VALUES (
                                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                            )
                            ON CONFLICT (question_id) DO UPDATE SET
                                session_code = EXCLUDED.session_code,
                                session = EXCLUDED.session,
                                year = EXCLUDED.year,
                                paper_code = EXCLUDED.paper_code,
                                variant = EXCLUDED.variant,
                                file_question = EXCLUDED.file_question,
                                subtopic = EXCLUDED.subtopic,
                                extracted_text = EXCLUDED.extracted_text,
                                image_base64 = EXCLUDED.image_base64,
                                image_key = COALESCE(EXCLUDED.image_key, questions.image_key),
                                image_url = COALESCE(EXCLUDED.image_url, questions.image_url),
                                answer = EXCLUDED.answer
                            """,
                            (
                                question_id,
                                row.get('SessionCode', '').strip(),
                                row.get('Session', '').strip(),
                                year,
                                row.get('PaperCode', '').strip(),
                                row.get('Variant', '').strip(),
                                row.get('File_Question', '').strip(),
                                row.get('Subtopic', '').strip(),
                                row.get('ExtractedText', '').strip(),
                                image_base64,
                                image_key,
                                image_url,
                                row.get('Answer', '').strip(),
                            ),
                        )

                        imported_count += 1
                        self.stdout.write(self.style.SUCCESS(f"Upserted QuestionID: {question_id}"))

                    except Exception as row_error:
                        self.stderr.write(self.style.ERROR(
                            f"Error importing QuestionID {row.get('QuestionID', 'Unknown')}: {row_error}"
                        ))

            self.stdout.write(self.style.SUCCESS(f"Import complete. Total imported: {imported_count}"))

        except FileNotFoundError:
            self.stderr.write(self.style.ERROR(f"CSV file not found at path: {csv_path}"))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Unexpected error: {e}"))
