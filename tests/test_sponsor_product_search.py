import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-database")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import app as sponsor_app
from product_api import EbayApiError, ExternalProduct


class SponsorProductSearchTests(unittest.TestCase):
    def setUp(self):
        self.config_patch = patch.dict(
            sponsor_app.app.config,
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key",
                "PRODUCT_API_PROVIDER": "ebay",
                "EBAY_SANDBOX": True,
            },
        )
        self.config_patch.start()

        self.context = sponsor_app.app.app_context()
        self.context.push()
        self.client = sponsor_app.app.test_client()

        self.auth_result = MagicMock()
        self.auth_result.first.return_value = (42,)

        self.db_patch = patch.object(
            sponsor_app.db.session,
            "execute",
            return_value=self.auth_result,
        )
        self.execute = self.db_patch.start()

        self.provider_patch = patch.object(
            sponsor_app, "get_product_search_client"
        )
        self.get_provider = self.provider_patch.start()
        self.provider = self.get_provider.return_value
        self.provider.search.return_value = []

    def tearDown(self):
        self.provider_patch.stop()
        self.db_patch.stop()
        sponsor_app.db.session.remove()
        self.context.pop()
        self.config_patch.stop()

    def sign_in(self, role="SPONSOR"):
        with self.client.session_transaction() as login_session:
            login_session["user_id"] = 42
            login_session["role"] = role

    def test_guest_redirects_without_database_or_api_call(self):
        response = self.client.get("/sponsor/products/search?q=thermos")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/login")
        self.execute.assert_not_called()
        self.get_provider.assert_not_called()

    def test_driver_is_rejected_without_api_call(self):
        self.sign_in("DRIVER")

        response = self.client.get("/sponsor/products/search?q=thermos")

        self.assertEqual(response.status_code, 403)
        self.execute.assert_not_called()
        self.get_provider.assert_not_called()

    def test_inactive_or_unassigned_sponsor_is_rejected(self):
        self.sign_in()
        self.auth_result.first.return_value = None

        response = self.client.get("/sponsor/products/search?q=thermos")

        self.assertEqual(response.status_code, 403)
        self.get_provider.assert_not_called()

    def test_blank_query_does_not_call_provider(self):
        self.sign_in()

        response = self.client.get("/sponsor/products/search?q=%20%20")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Enter a keyword", response.get_data(as_text=True))
        self.get_provider.assert_not_called()

    def test_long_query_is_rejected(self):
        self.sign_in()

        response = self.client.get(
            "/sponsor/products/search",
            query_string={"q": "x" * 101},
        )

        self.assertEqual(response.status_code, 400)
        self.get_provider.assert_not_called()

    def test_search_renders_results_and_escapes_external_text(self):
        self.sign_in()
        self.provider.search.return_value = [
            ExternalProduct(
                external_product_id="v1|123|0",
                title="Travel Thermos",
                description="<script>alert(1)</script>",
                price_usd=19.99,
                image_url=None,
            )
        ]

        response = self.client.get(
            "/sponsor/products/search",
            query_string={"q": "  thermos  "},
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("Travel Thermos", body)
        self.assertIn("$19.99 USD", body)
        self.assertIn("eBay Sandbox", body)
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)
        self.provider.search.assert_called_once_with("thermos")

    def test_empty_results_have_distinct_message(self):
        self.sign_in()

        response = self.client.get("/sponsor/products/search?q=thermos")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "No eligible USD products",
            response.get_data(as_text=True),
        )

    def test_api_failure_is_not_presented_as_empty_results(self):
        self.sign_in()
        self.provider.search.side_effect = EbayApiError("Test failure")

        response = self.client.get("/sponsor/products/search?q=thermos")

        self.assertEqual(response.status_code, 503)
        body = response.get_data(as_text=True)
        self.assertIn("Product search is unavailable", body)
        self.assertNotIn("No eligible USD products", body)


if __name__ == "__main__":
    unittest.main()