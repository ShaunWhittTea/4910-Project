import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-database")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import app as catalog_app
from product_api import FixtureProductApiClient


def result_for(count, rows):
    result = MagicMock()
    result.scalar_one.return_value = count
    result.mappings.return_value.all.return_value = rows
    return result


class CatalogTests(unittest.TestCase):
    def setUp(self):
        catalog_app.app.config.update(TESTING=True, SECRET_KEY="test-secret-key")
        self.context = catalog_app.app.app_context()
        self.context.push()
        self.client = catalog_app.app.test_client()

    def tearDown(self):
        catalog_app.db.session.remove()
        self.context.pop()

    def sign_in(self, role="DRIVER", sponsor_org_id=1):
        with self.client.session_transaction() as login_session:
            login_session["user_id"] = 2
            login_session["role"] = role
            login_session["sponsor_org_id"] = sponsor_org_id

    def test_guest_is_redirected_to_driver_login(self):
        response = self.client.get("/api/catalog/items")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/driver/login"))

    def test_sponsor_cannot_read_driver_catalog(self):
        self.sign_in(role="SPONSOR")
        response = self.client.get("/api/catalog/items")
        self.assertEqual(response.status_code, 403)

    def test_invalid_pagination_is_rejected_before_database_query(self):
        self.sign_in()
        with patch.object(catalog_app.db.session, "execute") as execute:
            for query in ("?page=0", "?page=abc", "?pageSize=0", "?pageSize=51"):
                with self.subTest(query=query):
                    response = self.client.get("/api/catalog/items" + query)
                    self.assertEqual(response.status_code, 400)
            execute.assert_not_called()

    def test_page_two_has_correct_offset_count_and_items(self):
        self.sign_in()
        rows = [{
            "catalog_item_id": 3,
            "external_product_id": "demo-003",
            "title": "Thermos",
            "description": "Travel thermos",
            "price_usd": 24.99,
            "image_url": None,
            "points_price": 2499,
        }]
        with patch.object(catalog_app.db.session, "execute", side_effect=[
            result_for(5, []), result_for(0, rows),
        ]) as execute:
            response = self.client.get("/api/catalog/items?page=2&pageSize=2")

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["pagination"], {
            "page": 2, "pageSize": 2, "totalItems": 5, "totalPages": 3,
        })
        self.assertEqual(body["items"][0]["title"], "Thermos")
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(execute.call_args_list[0].args[1], {"driver_user_id": 2})
        self.assertEqual(execute.call_args_list[1].args[1], {
            "driver_user_id": 2, "page_size": 2, "offset": 2,
        })
        self.assertIn("ci.sponsor_org_id = dp.sponsor_org_id", str(execute.call_args_list[1].args[0]))
        self.assertIn("ci.active = 1", str(execute.call_args_list[1].args[0]))

    def test_session_and_url_sponsor_ids_are_not_query_inputs(self):
        self.sign_in(sponsor_org_id=999)
        with patch.object(catalog_app.db.session, "execute", side_effect=[
            result_for(0, []), result_for(0, []),
        ]) as execute:
            response = self.client.get("/api/catalog/items?sponsor_org_id=888")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["items"], [])
        self.assertEqual(response.get_json()["pagination"]["totalPages"], 0)
        for call in execute.call_args_list:
            self.assertNotIn("sponsor_org_id", call.args[1])
            self.assertNotIn("999", str(call.args[1]))
            self.assertNotIn("888", str(call.args[1]))

    def test_fixture_client_contract(self):
        client = FixtureProductApiClient()
        results = client.search("HEADPHONES")
        self.assertEqual(len(results), 1)
        self.assertEqual(client.get_by_external_id(results[0].external_product_id), results[0])
        self.assertIsNone(client.get_by_external_id("nonexistent"))


if __name__ == "__main__":
    unittest.main()