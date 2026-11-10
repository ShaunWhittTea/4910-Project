import os
import unittest
from unittest.mock import MagicMock, patch


os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-database")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import app as driver_app


def mapping_first(row):
    result = MagicMock()
    result.mappings.return_value.first.return_value = row
    return result


def mapping_all(rows):
    result = MagicMock()
    result.mappings.return_value.all.return_value = rows
    return result


def normal_result():
    return MagicMock()


def insert_result(lastrowid):
    result = MagicMock()
    result.lastrowid = lastrowid
    return result


class DriverApplicationTests(unittest.TestCase):

    def setUp(self):
        driver_app.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret-key",
        )

        self.context = driver_app.app.app_context()
        self.context.push()

        self.client = driver_app.app.test_client()

    def tearDown(self):
        driver_app.db.session.remove()
        self.context.pop()

    def sign_in_sponsor(self):
        with self.client.session_transaction() as login_session:
            login_session["user_id"] = 100
            login_session["role"] = "SPONSOR"
            login_session["sponsor_org_id"] = 7

    def sign_in_driver(self):
        with self.client.session_transaction() as login_session:
            login_session["user_id"] = 42
            login_session["role"] = "DRIVER"
            login_session["sponsor_org_id"] = 7

    def test_completed_application_is_submitted_as_pending(self):

        organizations = mapping_all([
            {
                "sponsor_org_id": 7,
                "name": "Test Sponsor",
            }
        ])

        no_existing_user = MagicMock()
        no_existing_user.first.return_value = None

        new_driver = insert_result(42)
        application_insert = normal_result()

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    organizations,
                    no_existing_user,
                    new_driver,
                    application_insert,
                ],
            ) as execute,
            patch.object(
                driver_app.db.session,
                "commit",
            ) as commit,
        ):

            response = self.client.post(
                "/apply",
                data={
                    "action": "submit",
                    "first_name": "Test",
                    "last_name": "Driver",
                    "email": "driver@example.com",
                    "phone": "8645551234",
                    "has_license": "YES",
                    "sponsor_org_id": "7",
                    "password": "TestPassword1!",
                    "confirm_password": "TestPassword1!",
                },
            )

        self.assertEqual(response.status_code, 200)

        body = response.get_data(as_text=True)

        self.assertIn(
            "Application submitted successfully",
            body,
        )

        application_call = execute.call_args_list[3]

        sql = str(application_call.args[0])
        parameters = application_call.args[1]

        self.assertIn(
            "INSERT INTO driver_application",
            sql,
        )

        self.assertEqual(
            parameters["application_status"],
            "PENDING",
        )

        self.assertEqual(
            parameters["sponsor_org_id"],
            "7",
        )

        commit.assert_called_once()

    def test_pending_driver_can_view_application_status(self):

        self.sign_in_driver()

        pending_application = {
            "status": "PENDING",
            "decision_reason": None,
            "organization_name": "Test Sponsor",
        }

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=mapping_first(
                pending_application
            ),
        ):

            response = self.client.get(
                "/application/status"
            )

        self.assertEqual(
            response.status_code,
            200,
        )

        body = response.get_data(as_text=True)

        self.assertIn(
            "Application Pending",
            body,
        )

        self.assertIn(
            "Test Sponsor",
            body,
        )

    def test_sponsor_can_approve_application(self):

        self.sign_in_sponsor()

        pending_application = {
            "application_id": 10,
            "driver_user_id": 42,
        }

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    mapping_first(
                        pending_application
                    ),
                    normal_result(),
                    normal_result(),
                    normal_result(),
                ],
            ) as execute,
            patch.object(
                driver_app.db.session,
                "commit",
            ) as commit,
        ):

            response = self.client.post(
                "/sponsor/applications/10/approve"
            )

        self.assertEqual(
            response.status_code,
            302,
        )

        approval_sql = str(
            execute.call_args_list[1].args[0]
        )

        self.assertIn(
            "status = 'APPROVED'",
            approval_sql,
        )

        profile_sql = str(
            execute.call_args_list[2].args[0]
        )

        self.assertIn(
            "INSERT INTO driver_profile",
            profile_sql,
        )

        user_sql = str(
            execute.call_args_list[3].args[0]
        )

        self.assertIn(
            "status = 'ACTIVE'",
            user_sql,
        )

        commit.assert_called_once()

    def test_sponsor_can_reject_application_with_reason(self):

        self.sign_in_sponsor()

        pending_application = {
            "application_id": 10,
            "driver_user_id": 42,
        }

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    mapping_first(
                        pending_application
                    ),
                    normal_result(),
                ],
            ) as execute,
            patch.object(
                driver_app.db.session,
                "commit",
            ) as commit,
        ):

            response = self.client.post(
                "/sponsor/applications/10/reject",
                data={
                    "decision_reason":
                        "Driver information could not be verified."
                },
            )

        self.assertEqual(
            response.status_code,
            302,
        )

        rejection_call = execute.call_args_list[1]

        rejection_sql = str(
            rejection_call.args[0]
        )

        parameters = rejection_call.args[1]

        self.assertIn(
            "status = 'REJECTED'",
            rejection_sql,
        )

        self.assertIn(
            "decision_reason",
            rejection_sql,
        )

        self.assertEqual(
            parameters["decision_reason"],
            "Driver information could not be verified.",
        )

        commit.assert_called_once()

    def test_rejected_driver_can_view_rejection_reason(self):

        self.sign_in_driver()

        rejected_application = {
            "status": "REJECTED",
            "decision_reason":
                "Driver information could not be verified.",
            "organization_name": "Test Sponsor",
        }

        with patch.object(
            driver_app.db.session,
            "execute",
            return_value=mapping_first(
                rejected_application
            ),
        ):

            response = self.client.get(
                "/application/status"
            )

        self.assertEqual(
            response.status_code,
            200,
        )

        body = response.get_data(as_text=True)

        self.assertIn(
            "Application Not Approved",
            body,
        )

        self.assertIn(
            "Driver information could not be verified.",
            body,
        )

        self.assertIn(
            "Test Sponsor",
            body,
        )

    def test_existing_driver_cannot_create_second_application(self):

        organizations = mapping_all([
            {
                "sponsor_org_id": 8,
                "name": "Another Sponsor",
            }
        ])

        existing_user = MagicMock()
        existing_user.first.return_value = (42,)

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    organizations,
                    existing_user,
                ],
            ) as execute,
            patch.object(
                driver_app.db.session,
                "commit",
            ) as commit,
        ):

            response = self.client.post(
                "/apply",
                data={
                    "action": "submit",
                    "first_name": "Test",
                    "last_name": "Driver",
                    "email": "driver@example.com",
                    "phone": "8645551234",
                    "has_license": "YES",
                    "sponsor_org_id": "8",
                    "password": "TestPassword1!",
                    "confirm_password": "TestPassword1!",
                },
            )

        self.assertEqual(
            response.status_code,
            200,
        )

        body = response.get_data(as_text=True)

        self.assertIn(
            "An account with that email already exists.",
            body,
        )

        self.assertEqual(
            execute.call_count,
            2,
        )

        commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()