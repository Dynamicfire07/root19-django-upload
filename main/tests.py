import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from django.test import RequestFactory, SimpleTestCase

from . import views


class UpdateActivityTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user_id = "U1"
        self.question_id = "Q1"

    @patch("main.views.execute")
    @patch("main.views.get_or_create_activity")
    @patch("main.views.query_one")
    def test_first_answer_records_result(self, mock_query_one, mock_get_activity, mock_execute):
        """First answer attempt should be recorded and return status ok."""
        mock_query_one.return_value = {"user_id": self.user_id}
        mock_get_activity.return_value = {"solved": False, "time_started": None}
        payload = {
            "user_id": self.user_id,
            "question_id": self.question_id,
            "action": "answer",
            "correct": True,
        }
        request = self.factory.post(
            "/update-activity/",
            data=json.dumps(payload),
            content_type="application/json",
        )

        response = views.update_activity(request)
        body = json.loads(response.content.decode("utf-8"))

        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["solved"])
        self.assertTrue(body["correct"])
        mock_execute.assert_called_once_with(
            "UPDATE user_activity SET solved = %s, correct = %s, time_took = %s WHERE user_id = %s AND question_id = %s",
            (True, True, None, self.user_id, self.question_id),
        )

    @patch("main.views.execute")
    @patch("main.views.get_or_create_activity")
    @patch("main.views.query_one")
    def test_subsequent_answers_are_ignored(self, mock_query_one, mock_get_activity, mock_execute):
        """Once solved, additional answer submissions should be ignored."""
        mock_query_one.return_value = {"user_id": self.user_id}
        mock_get_activity.return_value = {"solved": True, "correct": False}
        payload = {
            "user_id": self.user_id,
            "question_id": self.question_id,
            "action": "answer",
            "correct": True,
        }
        request = self.factory.post(
            "/update-activity/",
            data=json.dumps(payload),
            content_type="application/json",
        )

        response = views.update_activity(request)
        body = json.loads(response.content.decode("utf-8"))

        self.assertEqual(body["status"], "ignored")
        self.assertTrue(body["already_solved"])
        self.assertFalse(body["correct"])
        mock_execute.assert_not_called()


class UpdateActivityValidationTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user_id = "U1"
        self.question_id = "Q1"

    def _post(self, payload):
        return self.factory.post(
            "/update-activity/",
            data=json.dumps(payload),
            content_type="application/json",
        )

    @patch("main.views.query_one")
    def test_missing_fields_returns_400(self, mock_query_one):
        request = self._post({})
        response = views.update_activity(request)
        self.assertEqual(response.status_code, 400)
        body = json.loads(response.content.decode("utf-8"))
        self.assertIn("error", body)
        mock_query_one.assert_not_called()

    @patch("main.views.query_one")
    def test_user_not_found_returns_404(self, mock_query_one):
        mock_query_one.return_value = None
        request = self._post(
            {"user_id": self.user_id, "question_id": self.question_id, "action": "start"}
        )
        response = views.update_activity(request)
        self.assertEqual(response.status_code, 404)
        body = json.loads(response.content.decode("utf-8"))
        self.assertEqual(body.get("error"), "User not found")

    @patch("main.views.query_one")
    @patch("main.views.get_or_create_activity")
    def test_invalid_action_returns_400(self, mock_get_activity, mock_query_one):
        mock_query_one.return_value = {"user_id": self.user_id}
        mock_get_activity.return_value = {}
        request = self._post(
            {
                "user_id": self.user_id,
                "question_id": self.question_id,
                "action": "unknown",
            }
        )
        response = views.update_activity(request)
        self.assertEqual(response.status_code, 400)
        body = json.loads(response.content.decode("utf-8"))
        self.assertEqual(body.get("error"), "Invalid action")

    @patch("main.views.execute")
    @patch("main.views.get_or_create_activity")
    @patch("main.views.query_one")
    def test_start_records_time_and_view(self, mock_query_one, mock_get_activity, mock_execute):
        mock_query_one.return_value = {"user_id": self.user_id}
        mock_get_activity.return_value = {"solved": False, "time_started": None}
        fixed_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed_now

        with patch("main.views.datetime", FixedDateTime):
            request = self._post(
                {"user_id": self.user_id, "question_id": self.question_id, "action": "start"}
            )
            response = views.update_activity(request)

        body = json.loads(response.content.decode("utf-8"))
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["time_started"], fixed_now.isoformat())
        mock_execute.assert_called_once_with(
            "UPDATE user_activity SET time_started = %s, times_viewed = times_viewed + 1 WHERE user_id = %s AND question_id = %s",
            (fixed_now, self.user_id, self.question_id),
        )

    @patch("main.views.execute")
    @patch("main.views.get_or_create_activity")
    @patch("main.views.query_one")
    def test_bookmark_toggles_state(self, mock_query_one, mock_get_activity, mock_execute):
        mock_query_one.return_value = {"user_id": self.user_id}
        mock_get_activity.return_value = {"bookmarked": False}
        request = self._post(
            {"user_id": self.user_id, "question_id": self.question_id, "action": "bookmark"}
        )
        response = views.update_activity(request)
        body = json.loads(response.content.decode("utf-8"))
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["bookmarked"])
        mock_execute.assert_called_once_with(
            "UPDATE user_activity SET bookmarked = %s WHERE user_id = %s AND question_id = %s",
            (True, self.user_id, self.question_id),
        )

    @patch("main.views.execute")
    @patch("main.views.get_or_create_activity")
    @patch("main.views.query_one")
    def test_star_toggles_state(self, mock_query_one, mock_get_activity, mock_execute):
        mock_query_one.return_value = {"user_id": self.user_id}
        mock_get_activity.return_value = {"starred": True}
        request = self._post(
            {"user_id": self.user_id, "question_id": self.question_id, "action": "star"}
        )
        response = views.update_activity(request)
        body = json.loads(response.content.decode("utf-8"))
        self.assertEqual(body["status"], "ok")
        self.assertFalse(body["starred"])
        mock_execute.assert_called_once_with(
            "UPDATE user_activity SET starred = %s WHERE user_id = %s AND question_id = %s",
            (False, self.user_id, self.question_id),
        )

    @patch("main.views.execute")
    @patch("main.views.get_or_create_activity")
    @patch("main.views.query_one")
    def test_answer_records_time_delta(self, mock_query_one, mock_get_activity, mock_execute):
        mock_query_one.return_value = {"user_id": self.user_id}
        started_at = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        fixed_now = started_at + timedelta(seconds=5)
        mock_get_activity.return_value = {"solved": False, "time_started": started_at}

        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed_now

        with patch("main.views.datetime", FixedDateTime):
            request = self._post(
                {
                    "user_id": self.user_id,
                    "question_id": self.question_id,
                    "action": "answer",
                    "correct": False,
                }
            )
            response = views.update_activity(request)

        body = json.loads(response.content.decode("utf-8"))
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["time_took"], str(fixed_now - started_at))
        mock_execute.assert_called_once_with(
            "UPDATE user_activity SET solved = %s, correct = %s, time_took = %s WHERE user_id = %s AND question_id = %s",
            (True, False, fixed_now - started_at, self.user_id, self.question_id),
        )


class CheckAnswerTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @patch("main.views.query_one")
    def test_correct_answer(self, mock_query_one):
        mock_query_one.return_value = {"answer": "A"}
        request = self.factory.post(
            "/check-answer/", data={"question_id": "Q1", "selected_answer": "A"}
        )
        response = views.check_answer(request)
        body = json.loads(response.content.decode("utf-8"))
        self.assertTrue(body["is_correct"])

    @patch("main.views.query_one")
    def test_incorrect_answer(self, mock_query_one):
        mock_query_one.return_value = {"answer": "B"}
        request = self.factory.post(
            "/check-answer/", data={"question_id": "Q1", "selected_answer": "A"}
        )
        response = views.check_answer(request)
        body = json.loads(response.content.decode("utf-8"))
        self.assertFalse(body["is_correct"])


class APIKeyProtectionTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_api_questions_requires_api_key(self):
        request = self.factory.get("/api/questions/")
        response = views.api_questions(request)
        self.assertEqual(response.status_code, 401)
        body = json.loads(response.content.decode("utf-8"))
        self.assertIn("API key required", body.get("error", ""))

    def test_api_question_detail_requires_api_key(self):
        request = self.factory.get("/api/questions/Q1/")
        response = views.api_question_detail(request, "Q1")
        self.assertEqual(response.status_code, 401)
        body = json.loads(response.content.decode("utf-8"))
        self.assertIn("API key required", body.get("error", ""))


class QuestionFilterSubjectTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_subject_label_maps_to_session_code(self):
        request = self.factory.get("/api/questions/?subject=Physics")
        conditions, params = views._build_question_api_filters(request, {"session_code"})
        self.assertIn("session_code = %s", conditions)
        self.assertIn("625", params)

    def test_invalid_subject_raises_error(self):
        request = self.factory.get("/api/questions/?subject=Astronomy")
        with self.assertRaises(ValueError):
            views._build_question_api_filters(request, {"session_code"})


class APIKeyExtractionTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_extract_api_key_from_query_param(self):
        request = self.factory.get("/api/questions/?api_key=r19_test_query")
        parsed = views._extract_api_key(request)
        self.assertEqual(parsed, "r19_test_query")
