from django.core.management.base import BaseCommand, CommandError

from main.db import execute, query_all, query_one
from main.question_images import ensure_question_image_columns
from main.supabase_storage import (
    is_supabase_storage_configured,
    upload_question_base64,
    StorageUploadError,
)


class Command(BaseCommand):
    help = "Backfill questions.image_key/image_url from existing questions.image_base64 payloads."

    @staticmethod
    def _render_progress(done: int, total: int, width: int = 30) -> str:
        if total <= 0:
            return f"[{'-' * width}] {done}/?"
        filled = int((done * width) / total)
        if filled > width:
            filled = width
        bar = "#" * filled + "-" * (width - filled)
        pct = (done / total) * 100
        return f"[{bar}] {done}/{total} ({pct:5.1f}%)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=100,
            help="How many rows to fetch from DB per batch.",
        )
        parser.add_argument(
            "--max-rows",
            type=int,
            default=0,
            help="Optional hard cap on rows to process (0 = all).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Compute uploads without writing DB updates.",
        )

    def handle(self, *args, **options):
        if not is_supabase_storage_configured():
            raise CommandError(
                "Supabase storage is not configured. "
                "Set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, and SUPABASE_STORAGE_BUCKET."
            )

        ensure_question_image_columns()

        batch_size = max(1, int(options.get("batch_size") or 100))
        max_rows = max(0, int(options.get("max_rows") or 0))
        dry_run = bool(options.get("dry_run"))
        pending_total = int(
            (query_one(
                """
                SELECT COUNT(*) AS cnt
                FROM questions
                WHERE COALESCE(image_base64, '') <> ''
                  AND COALESCE(image_url, '') = ''
                """
            ) or {}).get("cnt", 0)
            or 0
        )
        target_total = min(max_rows, pending_total) if max_rows else pending_total
        if target_total <= 0:
            self.stdout.write(self.style.SUCCESS("Nothing to backfill."))
            return

        processed = 0
        migrated = 0
        failed = 0
        last_qid = ""

        self.stdout.write(
            self.style.WARNING(
                "Starting question-image backfill "
                f"(batch_size={batch_size}, max_rows={max_rows or 'all'}, dry_run={dry_run}, pending={pending_total})"
            )
        )

        while True:
            rows = query_all(
                """
                SELECT question_id, image_base64
                FROM questions
                WHERE COALESCE(image_base64, '') <> ''
                  AND COALESCE(image_url, '') = ''
                  AND question_id > %s
                ORDER BY question_id
                LIMIT %s
                """,
                (last_qid, batch_size),
            )
            if not rows:
                break

            for row in rows:
                qid = row.get("question_id")
                image_base64 = row.get("image_base64") or ""
                last_qid = qid or last_qid

                if not qid:
                    failed += 1
                    continue

                try:
                    upload_meta = upload_question_base64(qid, image_base64)
                    if not dry_run:
                        execute(
                            "UPDATE questions SET image_key = %s, image_url = %s WHERE question_id = %s",
                            (upload_meta["image_key"], upload_meta["image_url"], qid),
                        )
                    migrated += 1
                    processed += 1
                    prefix = self._render_progress(processed, target_total)
                    mode = "DRY" if dry_run else "OK "
                    self.stdout.write(f"{prefix} {mode} {qid} -> {upload_meta['image_url']}")
                except StorageUploadError as exc:
                    failed += 1
                    processed += 1
                    prefix = self._render_progress(processed, target_total)
                    self.stderr.write(self.style.ERROR(f"{prefix} ERR {qid} -> {exc}"))

                if max_rows and processed >= max_rows:
                    break

            if max_rows and processed >= max_rows:
                break

        self.stdout.write(
            self.style.SUCCESS(
                f"Backfill done. processed={processed}, migrated={migrated}, failed={failed}, dry_run={dry_run}"
            )
        )
