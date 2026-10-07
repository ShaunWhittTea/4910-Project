import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from product_api import EbayApiError, EbayProductApiClient


def response(payload):
    return io.BytesIO(json.dumps(payload).encode("utf-8"))


class EbayProductApiClientTests(unittest.TestCase):
    def setUp(self):
        self.client = EbayProductApiClient("test-id", "test-secret")

    @patch("product_api.urlopen")
    def test_search_mints_token_and_normalizes_listing(self, open_url):
        open_url.side_effect = [
            response({"access_token": "fake-token", "expires_in": 7200}),
            response({
                "itemSummaries": [{
                    "itemId": "v1|123|0",
                    "title": "Travel thermos",
                    "shortDescription": "Keeps drinks warm",
                    "price": {"value": "19.99", "currency": "USD"},
                    "image": {"imageUrl": "https://example.test/thermos.jpg"},
                }]
            }),
        ]

        products = self.client.search("travel thermos")

        self.assertEqual(len(products), 1)
        self.assertEqual(products[0].external_product_id, "v1|123|0")
        self.assertEqual(products[0].price_usd, 19.99)
        token_request = open_url.call_args_list[0].args[0]
        search_request = open_url.call_args_list[1].args[0]
        self.assertEqual(token_request.get_method(), "POST")
        self.assertIn(b"grant_type=client_credentials", token_request.data)
        self.assertIn("q=travel+thermos", search_request.full_url)
        self.assertEqual(
            search_request.get_header("Authorization"),
            "Bearer fake-token",
        )

    @patch("product_api.urlopen")
    def test_reuses_token_and_skips_non_usd_listing(self, open_url):
        open_url.side_effect = [
            response({"access_token": "fake-token", "expires_in": 7200}),
            response({"itemSummaries": [{
                "itemId": "v1|456|0",
                "title": "Non-USD item",
                "price": {"value": "12.00", "currency": "EUR"},
            }]}),
            response({"itemSummaries": []}),
        ]

        self.assertEqual(self.client.search("first"), [])
        self.assertEqual(self.client.search("second"), [])
        self.assertEqual(open_url.call_count, 3)  # One token, two searches

    @patch("product_api.urlopen")
    def test_get_missing_item_returns_none(self, open_url):
        open_url.side_effect = [
            response({"access_token": "fake-token", "expires_in": 7200}),
            HTTPError(
                "https://api.ebay.com/buy/browse/v1/item/missing",
                404,
                "Not Found",
                {},
                None,
            ),
        ]

        self.assertIsNone(self.client.get_by_external_id("missing"))

    @patch("product_api.urlopen")
    def test_token_failure_does_not_look_like_empty_results(self, open_url):
        open_url.return_value = response({"error": "invalid_client"})

        with self.assertRaises(EbayApiError):
            self.client.search("thermos")

    @patch("product_api.urlopen")
    def test_blank_query_does_not_contact_ebay(self, open_url):
        self.assertEqual(self.client.search("   "), [])
        open_url.assert_not_called()


if __name__ == "__main__":
    unittest.main()