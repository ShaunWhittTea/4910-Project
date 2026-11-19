import os
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch


os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-database")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import app as driver_app


def active_driver_result():
    result = MagicMock()
    result.first.return_value = (1,)
    return result


def mapping_first(row):
    result = MagicMock()
    result.mappings.return_value.first.return_value = row
    return result


def mapping_all(rows):
    result = MagicMock()
    result.mappings.return_value.all.return_value = rows
    return result


def scalar_result(value):
    result = MagicMock()
    result.scalar_one.return_value = value
    return result


class DriverMultiSponsorAlertTests(unittest.TestCase):
    def setUp(self):
        driver_app.app.config.update(TESTING=True, SECRET_KEY="test-secret-key")
        self.context = driver_app.app.app_context()
        self.context.push()
        self.client = driver_app.app.test_client()
        with self.client.session_transaction() as login_session:
            login_session["user_id"] = 42
            login_session["role"] = "DRIVER"
            login_session["sponsor_org_id"] = 7

    def tearDown(self):
        driver_app.db.session.remove()
        self.context.pop()

    def test_dashboard_lists_sponsors_balances_and_unread_alerts(self):
        memberships = [
            {"sponsor_org_id": 7, "sponsor_name": "Safe Freight", "point_balance": 250},
            {"sponsor_org_id": 8, "sponsor_name": "Road Rewards", "point_balance": 90},
        ]
        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[
                active_driver_result(),
                mapping_all(memberships),
                scalar_result(3),
            ],
        ):
            response = self.client.get("/driver/dashboard")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Safe Freight", body)
        self.assertIn("Road Rewards", body)
        self.assertIn("90 points", body)
        self.assertIn("Alerts (3 new)", body)

    def test_driver_can_switch_selected_sponsor(self):
        with (
            patch.object(driver_app.db.session, "execute", return_value=active_driver_result()),
            patch.object(driver_app, "sync_selected_driver_membership", return_value=True) as sync,
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            response = self.client.post("/driver/sponsors/8/select")

        self.assertEqual(response.status_code, 302)
        sync.assert_called_once_with(42, 8)
        commit.assert_called_once_with()
        with self.client.session_transaction() as login_session:
            self.assertEqual(login_session["sponsor_org_id"], 8)

    def test_notifications_show_point_change_and_order_summary(self):
        preferences = {
            "point_alerts_enabled": True,
            "order_alerts_enabled": True,
        }
        notifications = [
            {
                "notification_id": 2,
                "notification_type": "POINT_CHANGE",
                "title": "Your points changed",
                "message": "+25 points. Your new balance is 275 points.",
                "created_at": datetime(2026, 11, 18, 10, 30),
                "read_at": None,
                "sponsor_name": "Safe Freight",
            },
            {
                "notification_id": 1,
                "notification_type": "ORDER_SUMMARY",
                "title": "Order #12 placed",
                "message": "You ordered a Travel Mug for 120 points.",
                "created_at": datetime(2026, 11, 17, 9, 0),
                "read_at": None,
                "sponsor_name": "Safe Freight",
            },
        ]
        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    active_driver_result(),
                    mapping_first(preferences),
                    mapping_all(notifications),
                    MagicMock(),
                ],
            ),
            patch.object(driver_app.db.session, "commit"),
        ):
            response = self.client.get("/driver/notifications")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Your points changed", body)
        self.assertIn("new balance is 275 points", body)
        self.assertIn("Order #12 placed", body)

    def test_driver_can_disable_point_alerts(self):
        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[active_driver_result(), MagicMock()],
            ) as execute,
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            response = self.client.post(
                "/driver/notifications",
                data={"order_alerts_enabled": "on"},
            )

        self.assertEqual(response.status_code, 302)
        parameters = execute.call_args_list[1].args[1]
        self.assertFalse(parameters["point_alerts_enabled"])
        self.assertTrue(parameters["order_alerts_enabled"])
        commit.assert_called_once_with()

    def test_point_history_shows_resulting_sponsor_balance(self):
        history = [{
            "point_change_id": 4,
            "points": 25,
            "reason": "Safe driving",
            "created_at": datetime(2026, 11, 18, 8, 0),
            "sponsor_name": "Safe Freight",
            "resulting_balance": 275,
        }]
        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[active_driver_result(), mapping_all(history)],
        ) as execute:
            response = self.client.get("/driver/point-history")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Balance After Change", body)
        self.assertIn("275", body)
        self.assertIn("SUM(pc.points) OVER", str(execute.call_args_list[1].args[0]))


if __name__ == "__main__":
    unittest.main()
