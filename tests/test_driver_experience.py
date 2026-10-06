import os
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from werkzeug.security import generate_password_hash


os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-database")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import app as driver_app


def query_result(row):
    """Build the small SQLAlchemy result interface used by the routes."""

    result = MagicMock()
    result.mappings.return_value.first.return_value = row
    return result


def query_rows_result(rows):
    """Build the SQLAlchemy result interface used for result lists."""

    result = MagicMock()
    result.mappings.return_value.all.return_value = rows
    return result


def active_driver_result():
    """Build the result returned by the active-driver authorization query."""

    result = MagicMock()
    result.first.return_value = (1,)
    return result


class DriverExperienceTests(unittest.TestCase):
    def setUp(self):
        driver_app.app.config.update(TESTING=True, SECRET_KEY="test-secret-key")
        self.context = driver_app.app.app_context()
        self.context.push()
        self.client = driver_app.app.test_client()

    def tearDown(self):
        driver_app.db.session.remove()
        self.context.pop()

    def sign_in_session(self, role="DRIVER"):
        with self.client.session_transaction() as session:
            session["user_id"] = 42
            session["role"] = role
            session["sponsor_org_id"] = 7

    def test_driver_profile_redirects_anonymous_user_to_login(self):
        response = self.client.get("/driver/profile")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/login"))

    def test_driver_profile_rejects_authenticated_non_driver(self):
        self.sign_in_session(role="SPONSOR")

        response = self.client.get("/driver/profile")

        self.assertEqual(response.status_code, 403)

    def test_driver_login_sets_driver_session_and_redirects(self):
        user = {
            "user_id": 42,
            "password_hash": generate_password_hash("correct-password"),
            "sponsor_org_id": 7,
            "status": "ACTIVE",
        }

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=query_result(user),
        ):
            response = self.client.post(
                "/driver/login",
                data={
                    "email": "Driver@Example.com",
                    "password": "correct-password",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/dashboard"))
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_id"], 42)
            self.assertEqual(session["role"], "DRIVER")
            self.assertEqual(session["sponsor_org_id"], 7)

    def test_shared_login_detects_driver_role_and_redirects(self):
        user = {
            "user_id": 42,
            "role": "DRIVER",
            "password_hash": generate_password_hash("correct-password"),
            "sponsor_org_id": 7,
            "status": "ACTIVE",
        }

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=query_result(user),
        ):
            response = self.client.post(
                "/login",
                data={
                    "email": "Driver@Example.com",
                    "password": "correct-password",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/dashboard"))
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_id"], 42)
            self.assertEqual(session["role"], "DRIVER")
            self.assertEqual(session["sponsor_org_id"], 7)

    def test_shared_login_returns_safe_failure_instead_of_server_error(self):
        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=query_result(None),
        ):
            response = self.client.post(
                "/login",
                data={
                    "email": "unknown@example.com",
                    "password": "wrong-password",
                },
            )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid email or password.", body)

    def test_shared_logout_clears_session(self):
        self.sign_in_session()

        response = self.client.post("/logout")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/login"))
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)
            self.assertNotIn("role", session)

    def test_unknown_user_and_wrong_password_receive_same_safe_message(self):
        known_user = {
            "user_id": 42,
            "password_hash": generate_password_hash("correct-password"),
            "sponsor_org_id": 7,
            "status": "ACTIVE",
        }

        responses = []
        for result in (query_result(None), query_result(known_user)):
            with patch.object(
                driver_app.db.session,
                "execute",
                return_value=result,
            ):
                responses.append(
                    self.client.post(
                        "/driver/login",
                        data={
                            "email": "driver@example.com",
                            "password": "wrong-password",
                        },
                    )
                )

        for response in responses:
            body = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn("Invalid email or password.", body)
            self.assertNotIn("account does not exist", body.lower())

    def test_inactive_driver_with_valid_password_receives_account_guidance(self):
        inactive_user = {
            "user_id": 42,
            "password_hash": generate_password_hash("correct-password"),
            "sponsor_org_id": 7,
            "status": "INACTIVE",
        }

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=query_result(inactive_user),
        ):
            response = self.client.post(
                "/driver/login",
                data={
                    "email": "driver@example.com",
                    "password": "correct-password",
                },
            )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(driver_app.ACCOUNT_UNAVAILABLE_MESSAGE, body)
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_inactive_driver_with_wrong_password_gets_generic_failure(self):
        inactive_user = {
            "user_id": 42,
            "password_hash": generate_password_hash("correct-password"),
            "sponsor_org_id": 7,
            "status": "INACTIVE",
        }

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=query_result(inactive_user),
        ):
            response = self.client.post(
                "/driver/login",
                data={
                    "email": "driver@example.com",
                    "password": "wrong-password",
                },
            )

        body = response.get_data(as_text=True)
        self.assertIn("Invalid email or password.", body)
        self.assertNotIn(driver_app.ACCOUNT_UNAVAILABLE_MESSAGE, body)

    def test_driver_logout_clears_session(self):
        self.sign_in_session()

        response = self.client.post("/driver/logout")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/login"))
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)
            self.assertNotIn("role", session)

    def test_driver_can_view_profile(self):
        self.sign_in_session()
        user = {
            "user_id": 42,
            "email": "driver@example.com",
            "first_name": "Drew",
            "last_name": "Driver",
            "phone": "555-0100",
            "shipping_address": "100 Main Street",
            "point_balance": 250,
            "sponsor_name": "Safe Freight",
        }

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=query_result(user),
        ):
            response = self.client.get("/driver/profile")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Drew", body)
        self.assertIn("Safe Freight", body)
        self.assertIn("250", body)

    def test_driver_can_update_editable_profile_fields(self):
        self.sign_in_session()
        updated_user = {
            "user_id": 42,
            "email": "new@example.com",
            "first_name": "New",
            "last_name": "Name",
            "phone": "555-0199",
            "shipping_address": "200 Oak Avenue",
            "point_balance": 250,
            "sponsor_name": "Safe Freight",
        }
        execute_results = [
            MagicMock(),
            MagicMock(),
            query_result(updated_user),
        ]

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[active_driver_result(), *execute_results],
            ) as execute,
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            response = self.client.post(
                "/driver/profile",
                data={
                    "first_name": "New",
                    "last_name": "Name",
                    "email": "NEW@example.com",
                    "phone": "555-0199",
                    "shipping_address": "200 Oak Avenue",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Profile updated successfully.", response.get_data(as_text=True))
        self.assertEqual(execute.call_count, 4)
        self.assertIn("UPDATE app_user", str(execute.call_args_list[1].args[0]))
        self.assertIn("UPDATE driver_profile", str(execute.call_args_list[2].args[0]))
        self.assertEqual(execute.call_args_list[1].args[1]["email"], "new@example.com")
        commit.assert_called_once_with()

    def test_invalid_profile_update_does_not_write(self):
        self.sign_in_session()
        current_user = {
            "user_id": 42,
            "email": "driver@example.com",
            "first_name": "Drew",
            "last_name": "Driver",
            "phone": None,
            "shipping_address": None,
            "point_balance": 250,
            "sponsor_name": "Safe Freight",
        }

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[active_driver_result(), query_result(current_user)],
            ) as execute,
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            response = self.client.post(
                "/driver/profile",
                data={
                    "first_name": "",
                    "last_name": "Driver",
                    "email": "driver@example.com",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("First name, last name, and email are required.", response.get_data(as_text=True))
        self.assertEqual(execute.call_count, 2)
        self.assertNotIn("UPDATE", str(execute.call_args_list[1].args[0]))
        commit.assert_not_called()

    def test_driver_point_history_requires_driver_account(self):
        response = self.client.get("/driver/point-history")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/login"))

        self.sign_in_session(role="SPONSOR")
        response = self.client.get("/driver/point-history")
        self.assertEqual(response.status_code, 403)

    def test_driver_sees_complete_point_history_with_required_details(self):
        self.sign_in_session()
        point_history = [
            {
                "point_change_id": 12,
                "points": 25,
                "reason": "Completed a safety course",
                "created_at": datetime(2026, 10, 5, 14, 30),
                "sponsor_name": "Safe Freight",
            },
            {
                "point_change_id": 11,
                "points": -10,
                "reason": "Late delivery",
                "created_at": datetime(2026, 10, 1, 9, 15),
                "sponsor_name": "Safe Freight",
            },
        ]

        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[active_driver_result(), query_rows_result(point_history)],
        ) as execute:
            response = self.client.get("/driver/point-history")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Addition +25", body)
        self.assertIn("Deduction -10", body)
        self.assertIn("Oct 05, 2026 at 02:30 PM", body)
        self.assertIn("Completed a safety course", body)
        self.assertIn("Safe Freight", body)

        history_query = str(execute.call_args_list[1].args[0])
        history_parameters = execute.call_args_list[1].args[1]
        self.assertIn("pc.driver_user_id = :driver_user_id", history_query)
        self.assertIn("pc.created_at DESC", history_query)
        self.assertEqual(history_parameters, {"driver_user_id": 42})
        self.assertNotIn("sponsor_org_id", history_parameters)

    def test_driver_point_history_has_an_empty_state(self):
        self.sign_in_session()

        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[active_driver_result(), query_rows_result([])],
        ):
            response = self.client.get("/driver/point-history")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("No point history yet", body)

    def test_password_complexity_reports_each_requirement(self):
        cases = {
            "Short1!": "at least 12 characters",
            "lowercasepassword1!": "an uppercase letter",
            "UPPERCASEPASSWORD1!": "a lowercase letter",
            "PasswordOnly!": "a number",
            "PasswordOnly1": "a special character",
        }

        for password, expected_error in cases.items():
            with self.subTest(password=password):
                self.assertIn(
                    expected_error,
                    driver_app.get_password_validation_errors(password),
                )

        self.assertEqual(
            driver_app.get_password_validation_errors("ValidPassword1!"),
            [],
        )

    def test_set_password_rejects_weak_password_before_database_write(self):
        runner = driver_app.app.test_cli_runner()

        with patch.object(driver_app.db.session, "execute") as execute:
            result = runner.invoke(
                args=["set-password", "driver@example.com"],
                input="weak\nweak\n",
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("at least 12 characters", result.output)
        execute.assert_not_called()

    def test_set_password_hashes_valid_complex_password(self):
        runner = driver_app.app.test_cli_runner()
        update_result = MagicMock(rowcount=1)

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                return_value=update_result,
            ) as execute,
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            result = runner.invoke(
                args=["set-password", "Driver@Example.com"],
                input="ValidPassword1!\nValidPassword1!\n",
            )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Password updated.", result.output)
        parameters = execute.call_args.args[1]
        self.assertEqual(parameters["email"], "driver@example.com")
        self.assertNotEqual(parameters["hash"], "ValidPassword1!")
        self.assertTrue(parameters["hash"].startswith("scrypt:"))
        commit.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
