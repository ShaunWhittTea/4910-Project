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


def query_result(row):
    result = MagicMock()
    result.mappings.return_value.first.return_value = row
    return result


def query_rows_result(rows):
    result = MagicMock()
    result.mappings.return_value.all.return_value = rows
    return result


def active_driver_result():
    result = MagicMock()
    result.first.return_value = (1,)
    return result


def sample_order(status="PLACED"):
    return {
        "order_id": 501,
        "status": status,
        "total_points": 1200,
        "total_usd": 12.00,
        "created_at": datetime(2026, 10, 20, 15, 45),
        "sponsor_name": "Safe Freight",
    }


def sample_lines():
    return [
        {
            "order_line_id": 1,
            "external_product_id": "reward-1",
            "title": "Travel Mug",
            "quantity": 2,
            "unit_price_usd": 6.00,
            "unit_points": 600,
        }
    ]


class DriverOrderTests(unittest.TestCase):
    def setUp(self):
        driver_app.app.config.update(TESTING=True, SECRET_KEY="test-secret-key")
        self.context = driver_app.app.app_context()
        self.context.push()
        self.client = driver_app.app.test_client()

    def tearDown(self):
        driver_app.db.session.remove()
        self.context.pop()

    def sign_in(self, role="DRIVER"):
        with self.client.session_transaction() as login_session:
            login_session["user_id"] = 42
            login_session["role"] = role
            login_session["sponsor_org_id"] = 7

    def test_purchase_history_requires_driver_account(self):
        response = self.client.get("/driver/orders")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/login"))

        self.sign_in(role="SPONSOR")
        response = self.client.get("/driver/orders")
        self.assertEqual(response.status_code, 403)

    def test_driver_sees_purchase_history_and_current_status(self):
        self.sign_in()
        orders = [sample_order(), sample_order(status="SHIPPED")]
        orders[1] = {**orders[1], "order_id": 500}

        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[active_driver_result(), query_rows_result(orders)],
        ) as execute:
            response = self.client.get("/driver/orders")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Order", body)
        self.assertIn("#501", body)
        self.assertIn("Placed", body)
        self.assertIn("Shipped", body)
        self.assertIn("Safe Freight", body)
        self.assertIn("1200", body)
        self.assertIn("View details", body)

        history_query = str(execute.call_args_list[1].args[0])
        history_parameters = execute.call_args_list[1].args[1]
        self.assertIn("po.driver_user_id = :driver_user_id", history_query)
        self.assertIn("po.created_at DESC", history_query)
        self.assertEqual(history_parameters, {"driver_user_id": 42})

    def test_purchase_history_has_empty_state(self):
        self.sign_in()

        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[active_driver_result(), query_rows_result([])],
        ):
            response = self.client.get("/driver/orders")

        self.assertEqual(response.status_code, 200)
        self.assertIn("No purchases yet", response.get_data(as_text=True))

    def test_driver_can_view_owned_purchase_details(self):
        self.sign_in()

        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[
                active_driver_result(),
                query_result(sample_order()),
                query_rows_result(sample_lines()),
            ],
        ) as execute:
            response = self.client.get("/driver/orders/501")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Order #501", body)
        self.assertIn("Purchase details and current order status.", body)
        self.assertIn("Travel Mug", body)
        self.assertIn("1200", body)
        self.assertIn("Cancel Order", body)

        detail_parameters = execute.call_args_list[1].args[1]
        lines_parameters = execute.call_args_list[2].args[1]
        expected = {"order_id": 501, "driver_user_id": 42}
        self.assertEqual(detail_parameters, expected)
        self.assertEqual(lines_parameters, expected)
        self.assertIn(
            "po.driver_user_id = :driver_user_id",
            str(execute.call_args_list[2].args[0]),
        )

    def test_driver_cannot_view_another_drivers_order(self):
        self.sign_in()

        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[active_driver_result(), query_result(None)],
        ) as execute:
            response = self.client.get("/driver/orders/999")

        self.assertEqual(response.status_code, 404)
        self.assertIn("Order not found.", response.get_data(as_text=True))
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(
            execute.call_args_list[1].args[1],
            {"order_id": 999, "driver_user_id": 42},
        )

    def test_placed_order_can_be_canceled_with_confirmation(self):
        self.sign_in()
        update_result = MagicMock(rowcount=1)
        refund_result = MagicMock(rowcount=1)
        point_change_result = MagicMock()
        canceled_order = sample_order(status="CANCELLED")

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    active_driver_result(),
                    query_result({
                        "order_id": 501,
                        "status": "PLACED",
                        "total_points": 1200,
                        "sponsor_org_id": 7,
                        "point_balance": 300,
                    }),
                    update_result,
                    refund_result,
                    point_change_result,
                    MagicMock(),
                    MagicMock(),
                    active_driver_result(),
                    query_result(canceled_order),
                    query_rows_result(sample_lines()),
                ],
            ) as execute,
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            response = self.client.post(
                "/driver/orders/501/cancel",
                follow_redirects=True,
            )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Order #501 was canceled successfully.", body)
        self.assertIn("Cancelled", body)
        self.assertNotIn("Cancel Order", body)
        commit.assert_called_once_with()

        update_query = str(execute.call_args_list[2].args[0])
        update_parameters = execute.call_args_list[2].args[1]
        self.assertIn("status = 'CANCELLED'", update_query)
        self.assertIn("status = 'PLACED'", update_query)
        self.assertIn("driver_user_id = :driver_user_id", update_query)
        self.assertEqual(
            update_parameters,
            {"order_id": 501, "driver_user_id": 42},
        )

        refund_query = str(execute.call_args_list[3].args[0])
        refund_parameters = execute.call_args_list[3].args[1]
        self.assertIn("point_balance = point_balance + :points", refund_query)
        self.assertEqual(refund_parameters["points"], 1200)
        self.assertEqual(refund_parameters["sponsor_org_id"], 7)

        cache_query = str(execute.call_args_list[4].args[0])
        self.assertIn("UPDATE driver_profile", cache_query)

        point_query = str(execute.call_args_list[5].args[0])
        point_parameters = execute.call_args_list[5].args[1]
        self.assertIn("INSERT INTO point_change", point_query)
        self.assertEqual(point_parameters["points"], 1200)
        self.assertIn("canceled order #501", point_parameters["reason"])

    def test_non_placed_order_cannot_be_canceled(self):
        self.sign_in()

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[
                    active_driver_result(),
                    query_result({"order_id": 501, "status": "SHIPPED"}),
                ],
            ) as execute,
            patch.object(driver_app.db.session, "commit") as commit,
            patch.object(driver_app.db.session, "rollback") as rollback,
        ):
            response = self.client.post("/driver/orders/501/cancel")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/orders/501"))
        self.assertEqual(execute.call_count, 2)
        commit.assert_not_called()
        rollback.assert_called_once_with()
        with self.client.session_transaction() as login_session:
            flashes = login_session.get("_flashes", [])
        self.assertIn("can no longer be canceled", flashes[0][1])

    def test_driver_cannot_cancel_another_drivers_order(self):
        self.sign_in()

        with (
            patch.object(
                driver_app.db.session,
                "execute",
                side_effect=[active_driver_result(), query_result(None)],
            ) as execute,
            patch.object(driver_app.db.session, "commit") as commit,
        ):
            response = self.client.post("/driver/orders/999/cancel")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(execute.call_count, 2)
        commit.assert_not_called()
        self.assertEqual(
            execute.call_args_list[1].args[1],
            {"order_id": 999, "driver_user_id": 42},
        )

    def test_cancel_button_only_appears_for_placed_orders(self):
        self.sign_in()

        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[
                active_driver_result(),
                query_result(sample_order(status="DELIVERED")),
                query_rows_result(sample_lines()),
            ],
        ):
            response = self.client.get("/driver/orders/501")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Cancel Order", body)
        self.assertIn("cannot be canceled", body)
        self.assertIn("Delivered", body)

    def get_history(self, rows=None, **query):
        self.sign_in()
        with patch.object(
            driver_app.db.session,
            "execute",
            side_effect=[
                active_driver_result(),
                query_rows_result(rows if rows is not None else []),
            ],
        ) as execute:
            response = self.client.get("/driver/orders", query_string=query)
        return response, execute

    def test_history_filters_use_bound_parameters_and_driver_scope(self):
        response, execute = self.get_history(
            q="mug",
            status="shipped",
            **{"from": "2026-10-01", "to": "2026-10-31"},
        )

        self.assertEqual(response.status_code, 200)
        query = str(execute.call_args_list[1].args[0])
        params = execute.call_args_list[1].args[1]
        self.assertIn("po.driver_user_id = :driver_user_id", query)
        self.assertIn("po.status = :status", query)
        self.assertIn("ESCAPE '!'", query)
        self.assertIn("po.created_at >= :date_from", query)
        self.assertIn("po.created_at < :date_to_end", query)
        self.assertNotIn("mug", query)
        self.assertEqual(
            params,
            {
                "driver_user_id": 42,
                "status": "SHIPPED",
                "keyword": "%mug%",
                "date_from": "2026-10-01",
                "date_to_end": "2026-11-01",
            },
        )

    def test_numeric_search_matches_order_number_or_item_name(self):
        response, execute = self.get_history(q="#501")

        self.assertEqual(response.status_code, 200)
        query = str(execute.call_args_list[1].args[0])
        params = execute.call_args_list[1].args[1]
        self.assertIn("po.order_id = :order_id", query)
        self.assertEqual(params["order_id"], 501)
        self.assertEqual(params["keyword"], "%#501%")

    def test_search_wildcards_are_treated_literally(self):
        response, execute = self.get_history(q="50%_")

        self.assertEqual(response.status_code, 200)
        params = execute.call_args_list[1].args[1]
        self.assertEqual(params["keyword"], "%50!%!_%")
        self.assertNotIn("order_id", params)

    def test_invalid_history_filters_are_rejected_before_querying(self):
        invalid_filters = [
            {"status": "DROP"},
            {"from": "2026-13-40"},
            {"to": "yesterday"},
            {"from": "2026-11-02", "to": "2026-11-01"},
            {"q": "x" * 101},
        ]
        self.sign_in()

        for query in invalid_filters:
            with self.subTest(query=query):
                with patch.object(
                    driver_app.db.session,
                    "execute",
                    side_effect=[active_driver_result()],
                ) as execute:
                    response = self.client.get(
                        "/driver/orders", query_string=query
                    )

                self.assertEqual(response.status_code, 400)
                self.assertEqual(execute.call_count, 1)

    def test_filtered_history_with_no_matches_keeps_controls(self):
        response, _ = self.get_history(q="zzznomatch")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("No matching purchases", body)
        self.assertNotIn("No purchases yet", body)
        self.assertIn('name="status"', body)
        self.assertIn('value="zzznomatch"', body)
        self.assertIn("Clear filters", body)

    def test_filters_do_not_change_unfiltered_empty_state(self):
        response, _ = self.get_history()

        self.assertIn("No purchases yet", response.get_data(as_text=True))

if __name__ == "__main__":
    unittest.main()
