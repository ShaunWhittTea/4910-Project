import os
import unittest
from unittest.mock import MagicMock, patch

from itsdangerous import SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash


os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-database")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import app as driver_app


def mapping_result(row):
    result = MagicMock()
    result.mappings.return_value.first.return_value = row
    return result


def active_driver_result():
    result = MagicMock()
    result.first.return_value = (1,)
    return result


def update_result(rowcount=1):
    result = MagicMock()
    result.rowcount = rowcount
    return result


class DriverPasswordTests(unittest.TestCase):
    def setUp(self):
        driver_app.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret-key",
            PASSWORD_RESET_MAX_AGE=1800,
            PASSWORD_RESET_SHOW_LINK=False,
        )
        self.context = driver_app.app.app_context()
        self.context.push()
        self.client = driver_app.app.test_client()

    def tearDown(self):
        driver_app.app.extensions.pop("password_reset_sender", None)
        driver_app.db.session.remove()
        self.context.pop()

    def sign_in_driver(self):
        with self.client.session_transaction() as login_session:
            login_session["user_id"] = 42
            login_session["role"] = "DRIVER"
            login_session["sponsor_org_id"] = 7

    def test_forgot_password_uses_generic_response_and_sends_link(self):
        password_hash = generate_password_hash("CurrentPassword1!")
        user = {
            "user_id": 42,
            "email": "driver@example.com",
            "first_name": "Test",
            "password_hash": password_hash,
        }
        sender = MagicMock()
        driver_app.app.extensions["password_reset_sender"] = sender

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=mapping_result(user),
        ):
            response = self.client.post(
                "/driver/password/forgot",
                data={"email": "Driver@Example.com"},
            )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(driver_app.PASSWORD_RESET_REQUEST_MESSAGE, body)
        self.assertIn("Local testing link", body)
        sender.assert_called_once()
        self.assertEqual(sender.call_args.kwargs["email"], "driver@example.com")
        self.assertIn(
            "/driver/password/reset/",
            sender.call_args.kwargs["reset_url"],
        )

    def test_unknown_email_receives_same_generic_response(self):
        sender = MagicMock()
        driver_app.app.extensions["password_reset_sender"] = sender

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=mapping_result(None),
        ):
            response = self.client.post(
                "/driver/password/forgot",
                data={"email": "unknown@example.com"},
            )

        self.assertIn(
            driver_app.PASSWORD_RESET_REQUEST_MESSAGE,
            response.get_data(as_text=True),
        )
        sender.assert_not_called()

    def test_invalid_and_expired_reset_tokens_show_recovery_guidance(self):
        invalid_response = self.client.get(
            "/driver/password/reset/not-a-valid-token"
        )
        self.assertIn(
            driver_app.INVALID_RESET_LINK_MESSAGE,
            invalid_response.get_data(as_text=True),
        )
        self.assertIn(
            "Request a New Reset Link",
            invalid_response.get_data(as_text=True),
        )

        serializer = MagicMock()
        serializer.loads.side_effect = SignatureExpired("expired")
        with patch.object(
            driver_app,
            "get_password_reset_serializer",
            return_value=serializer,
        ):
            self.assertIsNone(
                driver_app.get_password_reset_payload("expired-token")
            )

    def test_valid_reset_changes_hash_and_redirects_to_login(self):
        current_hash = generate_password_hash("CurrentPassword1!")
        token = driver_app.create_password_reset_token(42, current_hash)
        user = {"user_id": 42, "password_hash": current_hash}
        password_update = update_result()

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    mapping_result(user),
                    password_update,
                    MagicMock(),
                ],
            ) as execute,
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            response = self.client.post(
                f"/driver/password/reset/{token}",
                data={
                    "new_password": "NewPassword2!",
                    "confirm_password": "NewPassword2!",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login?password_reset=success", response.location)
        parameters = execute.call_args_list[1].args[1]
        self.assertTrue(
            check_password_hash(
                parameters["new_password_hash"],
                "NewPassword2!",
            )
        )
        self.assertIn("INSERT INTO audit_log", str(execute.call_args_list[2].args[0]))
        commit.assert_called_once()

    def test_reset_token_is_rejected_after_password_has_changed(self):
        old_hash = generate_password_hash("CurrentPassword1!")
        new_hash = generate_password_hash("NewPassword2!")
        token = driver_app.create_password_reset_token(42, old_hash)

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=mapping_result(
                {"user_id": 42, "password_hash": new_hash}
            ),
        ):
            response = self.client.get(f"/driver/password/reset/{token}")

        self.assertIn(
            driver_app.INVALID_RESET_LINK_MESSAGE,
            response.get_data(as_text=True),
        )

    def test_change_password_verifies_current_password_and_audits(self):
        self.sign_in_driver()
        current_hash = generate_password_hash("CurrentPassword1!")

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    active_driver_result(),
                    mapping_result({"password_hash": current_hash}),
                    update_result(),
                    MagicMock(),
                ],
            ) as execute,
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            response = self.client.post(
                "/driver/password/change",
                data={
                    "current_password": "CurrentPassword1!",
                    "new_password": "NewPassword2!",
                    "confirm_password": "NewPassword2!",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/profile"))
        self.assertIn("UPDATE app_user", str(execute.call_args_list[2].args[0]))
        self.assertIn("INSERT INTO audit_log", str(execute.call_args_list[3].args[0]))
        commit.assert_called_once()

    def test_change_password_rejects_wrong_current_password(self):
        self.sign_in_driver()
        current_hash = generate_password_hash("CurrentPassword1!")

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    active_driver_result(),
                    mapping_result({"password_hash": current_hash}),
                ],
            ),
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            response = self.client.post(
                "/driver/password/change",
                data={
                    "current_password": "WrongPassword1!",
                    "new_password": "NewPassword2!",
                    "confirm_password": "NewPassword2!",
                },
            )

        self.assertIn(
            "Current password is incorrect.",
            response.get_data(as_text=True),
        )
        commit.assert_not_called()

    def test_change_password_page_displays_every_requirement(self):
        self.sign_in_driver()

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=active_driver_result(),
        ):
            response = self.client.get("/driver/password/change")

        body = response.get_data(as_text=True)
        for requirement in driver_app.get_password_requirements():
            self.assertIn(requirement, body)


if __name__ == "__main__":
    unittest.main()
