import os
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch


os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-database")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import app as catalog_app


def query_result(row):
    result = MagicMock()
    result.mappings.return_value.first.return_value = row
    return result


def active_driver_result():
    result = MagicMock()
    result.first.return_value = (1,)
    return result


def sample_item(point_balance=5000):
    return {
        "catalog_item_id": 3,
        "external_product_id": "demo-003",
        "title": "Rechargeable Flashlight",
        "price_usd": Decimal("18.99"),
        "sponsor_org_id": 7,
        "point_balance": point_balance,
        "points_price": 1899,
    }


class CatalogPurchaseTests(unittest.TestCase):
    def setUp(self):
        catalog_app.app.config.update(TESTING=True, SECRET_KEY="test-secret-key")
        self.context = catalog_app.app.app_context()
        self.context.push()
        self.client = catalog_app.app.test_client()

    def tearDown(self):
        catalog_app.db.session.remove()
        self.context.pop()

    def sign_in(self, role="DRIVER"):
        with self.client.session_transaction() as login_session:
            login_session["user_id"] = 42
            login_session["role"] = role
            login_session["sponsor_org_id"] = 999

    def test_purchase_requires_driver_account(self):
        response = self.client.post("/driver/catalog/3/purchase")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/login"))

        self.sign_in(role="SPONSOR")
        response = self.client.post("/driver/catalog/3/purchase")
        self.assertEqual(response.status_code, 403)

    def test_driver_can_purchase_catalog_item(self):
        self.sign_in()
        balance_result = MagicMock(rowcount=1)
        order_result = MagicMock(lastrowid=777)
        line_result = MagicMock()
        point_result = MagicMock()

        with (
            patch.object(
                catalog_app.db.session,
                "execute",
                side_effect=[
                    active_driver_result(),
                    query_result(sample_item()),
                    balance_result,
                    order_result,
                    line_result,
                    point_result,
                ],
            ) as execute,
            patch.object(catalog_app.db.session, "commit") as commit,
        ):
            response = self.client.post("/driver/catalog/3/purchase")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/orders/777"))
        commit.assert_called_once_with()

        lookup_query = str(execute.call_args_list[1].args[0])
        lookup_parameters = execute.call_args_list[1].args[1]
        self.assertIn("ci.sponsor_org_id = dp.sponsor_org_id", lookup_query)
        self.assertIn("ci.active = 1", lookup_query)
        self.assertEqual(lookup_parameters, {
            "catalog_item_id": 3,
            "driver_user_id": 42,
        })
        self.assertNotIn("999", str(lookup_parameters))

        balance_query = str(execute.call_args_list[2].args[0])
        balance_parameters = execute.call_args_list[2].args[1]
        self.assertIn("point_balance = point_balance - :points_price", balance_query)
        self.assertEqual(balance_parameters["points_price"], 1899)

        order_query = str(execute.call_args_list[3].args[0])
        self.assertIn("INSERT INTO purchase_order", order_query)
        self.assertIn("'PLACED'", order_query)

        line_query = str(execute.call_args_list[4].args[0])
        line_parameters = execute.call_args_list[4].args[1]
        self.assertIn("INSERT INTO order_line", line_query)
        self.assertEqual(line_parameters["order_id"], 777)
        self.assertEqual(line_parameters["title"], "Rechargeable Flashlight")

        point_query = str(execute.call_args_list[5].args[0])
        self.assertIn("INSERT INTO point_change", point_query)
        self.assertIn("-:points_price", point_query)

        with self.client.session_transaction() as login_session:
            flashes = login_session.get("_flashes", [])
        self.assertIn("purchased successfully", flashes[0][1])
        self.assertIn("1899 points", flashes[0][1])

    def test_purchase_rejects_insufficient_points(self):
        self.sign_in()

        with (
            patch.object(
                catalog_app.db.session,
                "execute",
                side_effect=[
                    active_driver_result(),
                    query_result(sample_item(point_balance=300)),
                ],
            ) as execute,
            patch.object(catalog_app.db.session, "commit") as commit,
            patch.object(catalog_app.db.session, "rollback") as rollback,
        ):
            response = self.client.post("/driver/catalog/3/purchase")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/catalog"))
        self.assertEqual(execute.call_count, 2)
        commit.assert_not_called()
        rollback.assert_called_once_with()
        with self.client.session_transaction() as login_session:
            flashes = login_session.get("_flashes", [])
        self.assertIn("need 1899 points", flashes[0][1])
        self.assertIn("balance is 300 points", flashes[0][1])

    def test_driver_cannot_purchase_another_sponsors_item(self):
        self.sign_in()

        with (
            patch.object(
                catalog_app.db.session,
                "execute",
                side_effect=[active_driver_result(), query_result(None)],
            ) as execute,
            patch.object(catalog_app.db.session, "commit") as commit,
        ):
            response = self.client.post("/driver/catalog/999/purchase")

        self.assertEqual(response.status_code, 404)
        self.assertIn("Catalog item not found.", response.get_data(as_text=True))
        self.assertEqual(execute.call_count, 2)
        commit.assert_not_called()
        self.assertEqual(
            execute.call_args_list[1].args[1],
            {"catalog_item_id": 999, "driver_user_id": 42},
        )

    def test_balance_race_does_not_create_order(self):
        self.sign_in()
        balance_result = MagicMock(rowcount=0)

        with (
            patch.object(
                catalog_app.db.session,
                "execute",
                side_effect=[
                    active_driver_result(),
                    query_result(sample_item()),
                    balance_result,
                ],
            ) as execute,
            patch.object(catalog_app.db.session, "commit") as commit,
            patch.object(catalog_app.db.session, "rollback") as rollback,
        ):
            response = self.client.post("/driver/catalog/3/purchase")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/catalog"))
        self.assertEqual(execute.call_count, 3)
        commit.assert_not_called()
        rollback.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
