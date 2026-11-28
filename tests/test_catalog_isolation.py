import math
import os
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-database")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import app as catalog_app


SCHEMA = """
CREATE TABLE sponsor_org (
    sponsor_org_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    point_dollar_value NUMERIC NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE app_user (
    user_id INTEGER PRIMARY KEY,
    role TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE driver_profile (
    user_id INTEGER PRIMARY KEY,
    sponsor_org_id INTEGER NOT NULL,
    point_balance INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE catalog_item (
    catalog_item_id INTEGER PRIMARY KEY,
    sponsor_org_id INTEGER NOT NULL,
    external_product_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    price_usd NUMERIC NOT NULL,
    image_url TEXT,
    active INTEGER NOT NULL
);
"""


class CatalogIsolationTests(unittest.TestCase):
    def setUp(self):
        catalog_app.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret-key",
        )
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        @event.listens_for(self.engine, "connect")
        def register_ceiling(dbapi_connection, _):
            dbapi_connection.create_function("CEILING", 1, math.ceil)

        with self.engine.begin() as connection:
            for statement in SCHEMA.strip().split(";"):
                if statement.strip():
                    connection.execute(text(statement))

            connection.execute(text("""
                INSERT INTO sponsor_org
                    (sponsor_org_id, name, point_dollar_value, status)
                VALUES
                    (1, 'Sponsor A', 0.01, 'ACTIVE'),
                    (2, 'Sponsor B', 0.02, 'ACTIVE')
            """))

            connection.execute(text("""
                INSERT INTO app_user (user_id, role, status)
                VALUES
                    (101, 'DRIVER', 'ACTIVE'),
                    (202, 'DRIVER', 'ACTIVE'),
                    (303, 'DRIVER', 'INACTIVE')
            """))

            connection.execute(text("""
                INSERT INTO driver_profile (user_id, sponsor_org_id)
                VALUES
                    (101, 1),
                    (202, 2),
                    (303, 1)
            """))

            connection.execute(text("""
                INSERT INTO catalog_item (
                    catalog_item_id,
                    sponsor_org_id,
                    external_product_id,
                    title,
                    description,
                    price_usd,
                    image_url,
                    active
                )
                VALUES
                    (1, 1, 'a-1', 'Sponsor A Item 1', NULL, 10.00, NULL, 1),
                    (2, 1, 'a-2', 'Sponsor A Item 2', NULL, 20.00, NULL, 1),
                    (3, 1, 'a-hidden', 'Inactive A Item', NULL, 30.00, NULL, 0),
                    (4, 2, 'b-1', 'Sponsor B Item', NULL, 15.00, NULL, 1)
            """))

        self.database_session = Session(self.engine)
        self.client = catalog_app.app.test_client()

        self.execute_patch = patch.object(
            catalog_app.db.session,
            "execute",
            side_effect=self.database_session.execute,
        )
        self.execute_patch.start()

    def tearDown(self):
        self.execute_patch.stop()
        self.database_session.close()
        self.engine.dispose()

    def sign_in(self, user_id, fake_sponsor_id):
        with self.client.session_transaction() as login_session:
            login_session.clear()
            login_session["user_id"] = user_id
            login_session["role"] = "DRIVER"
            login_session["sponsor_org_id"] = fake_sponsor_id

    def test_driver_a_sees_only_sponsor_a_items(self):
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get(
            "/api/catalog/items?page=1&pageSize=1&sponsor_org_id=2"
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()

        self.assertEqual(body["pagination"]["totalItems"], 2)
        self.assertEqual(body["pagination"]["totalPages"], 2)
        self.assertEqual(body["items"][0]["title"], "Sponsor A Item 1")

        next_page = self.client.get(
            "/api/catalog/items?page=2&pageSize=1"
        ).get_json()
        self.assertEqual(next_page["items"][0]["title"], "Sponsor A Item 2")

        self.assertNotIn("Sponsor B Item", str(body) + str(next_page))
        self.assertNotIn("Inactive A Item", str(body) + str(next_page))

    def test_driver_b_sees_only_sponsor_b_items(self):
        self.sign_in(user_id=202, fake_sponsor_id=1)

        response = self.client.get(
            "/api/catalog/items?sponsor_org_id=1"
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()

        self.assertEqual(body["pagination"]["totalItems"], 1)
        self.assertEqual(
            [item["title"] for item in body["items"]],
            ["Sponsor B Item"],
        )
        self.assertNotIn("Sponsor A Item", str(body))

    def test_inactive_driver_is_denied_catalog_access(self):
        self.sign_in(user_id=303, fake_sponsor_id=1)

        response = self.client.get("/api/catalog/items")

        self.assertEqual(response.status_code, 403)
    def test_keyword_category_sort_and_pagination_work_together(self):
        self.database_session.execute(
            text("""
                UPDATE catalog_item
                SET category = 'Equipment',
                    description = 'Long haul reward'
                WHERE catalog_item_id IN (1, 2, 4)
            """)
        )

        with catalog_app.app.app_context():
            first_page, total = catalog_app.get_driver_catalog_page(
                driver_user_id=101,
                page=1,
                page_size=1,
                query="LONG HAUL",
                category="Equipment",
                sort="points_desc",
            )

            second_page, second_total = (
                catalog_app.get_driver_catalog_page(
                    driver_user_id=101,
                    page=2,
                    page_size=1,
                    query="LONG HAUL",
                    category="Equipment",
                    sort="points_desc",
                )
            )

        self.assertEqual(total, 2)
        self.assertEqual(second_total, 2)
        self.assertEqual(first_page[0]["catalog_item_id"], 2)
        self.assertEqual(second_page[0]["catalog_item_id"], 1)

        returned_ids = [
            item["catalog_item_id"]
            for item in first_page + second_page
        ]
        self.assertNotIn(4, returned_ids)

    def test_category_without_matches_returns_empty_page(self):
        with catalog_app.app.app_context():
            items, total = catalog_app.get_driver_catalog_page(
                driver_user_id=101,
                page=1,
                page_size=12,
                category="No Such Category",
            )

        self.assertEqual(items, [])
        self.assertEqual(total, 0)

    def test_keyword_wildcards_are_treated_literally(self):
        self.database_session.execute(
            text("""
                UPDATE catalog_item
                SET title = '100% Reward'
                WHERE catalog_item_id = 1
            """)
        )

        with catalog_app.app.app_context():
            items, total = catalog_app.get_driver_catalog_page(
                driver_user_id=101,
                page=1,
                page_size=12,
                query="%",
            )

        self.assertEqual(total, 1)
        self.assertEqual(items[0]["catalog_item_id"], 1)

    def test_name_sort_uses_requested_direction(self):
        self.database_session.execute(
            text("""
                UPDATE catalog_item
                SET title = CASE catalog_item_id
                    WHEN 1 THEN 'Zulu Reward'
                    WHEN 2 THEN 'Alpha Reward'
                    ELSE title
                END
            """)
        )

        with catalog_app.app.app_context():
            items, total = catalog_app.get_driver_catalog_page(
                driver_user_id=101,
                page=1,
                page_size=12,
                sort="name_asc",
            )

        self.assertEqual(total, 2)
        self.assertEqual(
            [item["catalog_item_id"] for item in items],
            [2, 1],
        )

    def test_invalid_catalog_options_are_rejected(self):
        invalid_options = [
            {"sort": "unexpected_sort"},
            {"query": "x" * 101},
            {"category": "x" * 121},
        ]

        with catalog_app.app.app_context():
            for options in invalid_options:
                with self.subTest(options=options):
                    with self.assertRaises(ValueError):
                        catalog_app.get_driver_catalog_page(
                            driver_user_id=101,
                            page=1,
                            page_size=12,
                            **options,
                        )

    def test_filtered_empty_catalog_shows_no_matches_and_controls(self):
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get(
            "/driver/catalog",
            query_string={"q": "zzznomatch987"},
        )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("No matching rewards", body)
        self.assertNotIn("No rewards are available yet", body)
        self.assertIn('name="q"', body)
        self.assertIn('name="category"', body)
        self.assertIn("Clear filters", body)

    def test_unfiltered_empty_catalog_shows_catalog_empty_state(self):
        self.database_session.execute(
            text("""
                UPDATE catalog_item
                SET active = 0
                WHERE sponsor_org_id = 1
            """)
        )
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get("/driver/catalog")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("No rewards are available yet", body)
        self.assertNotIn("No matching rewards", body)

    def test_category_choices_exclude_other_sponsors_and_inactive_items(self):
        self.database_session.execute(
            text("""
                UPDATE catalog_item
                SET category = CASE catalog_item_id
                    WHEN 1 THEN 'Electronics'
                    WHEN 2 THEN 'Drinkware'
                    WHEN 3 THEN 'Inactive Only'
                    WHEN 4 THEN 'Other Sponsor Only'
                END
            """)
        )

        with catalog_app.app.app_context():
            categories = catalog_app.get_driver_catalog_categories(101)

        self.assertEqual(categories, ["Drinkware", "Electronics"])

    def test_category_choices_exclude_missing_and_blank_values(self):
        for blank_value in (None, "", "   "):
            with self.subTest(category=blank_value):
                self.database_session.execute(
                    text("""
                        UPDATE catalog_item
                        SET category = :category
                        WHERE sponsor_org_id = 1
                    """),
                    {"category": blank_value},
                )

                with catalog_app.app.app_context():
                    categories = (
                        catalog_app.get_driver_catalog_categories(101)
                    )

                self.assertEqual(categories, [])

    def test_html_category_filter_displays_only_matching_sponsor_items(self):
        self.database_session.execute(
            text("""
                UPDATE catalog_item
                SET category = CASE catalog_item_id
                    WHEN 1 THEN 'Electronics'
                    WHEN 2 THEN 'Drinkware'
                    WHEN 3 THEN 'Electronics'
                    WHEN 4 THEN 'Electronics'
                END
            """)
        )
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get(
            "/driver/catalog",
            query_string={
                "category": "Electronics",
                "sort": "name_asc",
            },
        )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Sponsor A Item 1", body)
        self.assertNotIn("Sponsor A Item 2", body)
        self.assertNotIn("Inactive A Item", body)
        self.assertNotIn("Sponsor B Item", body)
        self.assertIn("Electronics", body)
        self.assertIn("Drinkware", body)

    def test_points_ranges_are_inclusive_and_sponsor_scoped(self):
        cases = [
            ({}, [1, 2]),
            ({"minPoints": 1000, "maxPoints": 1000}, [1]),
            ({"minPoints": 1001}, [2]),
            ({"maxPoints": 1000}, [1]),
            ({"minPoints": 0, "maxPoints": 0}, []),
            ({"minPoints": 500, "maxPoints": 900}, []),
        ]
        self.sign_in(user_id=101, fake_sponsor_id=2)

        for bounds, expected_ids in cases:
            with self.subTest(bounds=bounds):
                response = self.client.get(
                    "/api/catalog/items",
                    query_string=bounds,
                )

                self.assertEqual(response.status_code, 200)
                body = response.get_json()
                self.assertEqual(
                    [
                        item["catalog_item_id"]
                        for item in body["items"]
                    ],
                    expected_ids,
                )
                self.assertEqual(
                    body["pagination"]["totalItems"],
                    len(expected_ids),
                )

    def test_points_range_uses_the_drivers_sponsor_conversion(self):
        self.sign_in(user_id=202, fake_sponsor_id=1)

        response = self.client.get(
            "/api/catalog/items",
            query_string={"minPoints": 750, "maxPoints": 750},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [
                item["catalog_item_id"]
                for item in response.get_json()["items"]
            ],
            [4],
        )

    def test_invalid_points_ranges_return_400_on_both_routes(self):
        self.sign_in(user_id=101, fake_sponsor_id=2)
        cases = [
            {"minPoints": "-1"},
            {"maxPoints": "1.5"},
            {"minPoints": "abc"},
            {"maxPoints": "2147483648"},
            {"minPoints": "2000", "maxPoints": "1000"},
        ]

        for route in ("/api/catalog/items", "/driver/catalog"):
            for bounds in cases:
                with self.subTest(route=route, bounds=bounds):
                    response = self.client.get(
                        route,
                        query_string=bounds,
                    )
                    self.assertEqual(response.status_code, 400)

    def test_points_range_combines_with_existing_controls(self):
        self.database_session.execute(
            text("""
                UPDATE catalog_item
                SET category = 'Equipment'
            """)
        )
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get(
            "/api/catalog/items",
            query_string={
                "q": "Sponsor",
                "category": "Equipment",
                "sort": "points_desc",
                "minPoints": 1000,
                "maxPoints": 2000,
                "pageSize": 1,
                "page": 2,
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["pagination"]["totalItems"], 2)
        self.assertEqual(body["pagination"]["totalPages"], 2)
        self.assertEqual(body["items"][0]["catalog_item_id"], 1)

    def test_points_only_empty_search_shows_no_matching_rewards(self):
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get(
            "/driver/catalog",
            query_string={"maxPoints": 0},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "No matching rewards",
            response.get_data(as_text=True),
        )

    def test_driver_can_view_own_sponsor_product_details(self):
        self.database_session.execute(
            text("""
                UPDATE catalog_item
                SET description = 'Full reward description.',
                    category = 'Electronics'
                WHERE catalog_item_id = 1
            """)
        )
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get("/driver/catalog/1")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Sponsor A Item 1", body)
        self.assertIn("Full reward description.", body)
        self.assertIn("Electronics", body)
        self.assertIn("1000 points", body)
        self.assertIn("No image available", body)
        self.assertIn("Back to catalog", body)

    def test_product_detail_hides_foreign_inactive_and_missing_items(self):
        self.sign_in(user_id=101, fake_sponsor_id=2)

        for item_id in (3, 4, 999):
            with self.subTest(item_id=item_id):
                response = self.client.get(
                    f"/driver/catalog/{item_id}",
                    query_string={"sponsor_org_id": 2},
                )

                self.assertEqual(response.status_code, 404)
                self.assertEqual(
                    response.get_data(as_text=True),
                    "Catalog item not found.",
                )

    def test_product_detail_requires_driver_account(self):
        response = self.client.get("/driver/catalog/1")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response.location.endswith("/driver/login")
        )

        with self.client.session_transaction() as login_session:
            login_session["user_id"] = 101
            login_session["role"] = "SPONSOR"

        response = self.client.get("/driver/catalog/1")
        self.assertEqual(response.status_code, 403)

    def test_inactive_driver_cannot_view_product_details(self):
        self.sign_in(user_id=303, fake_sponsor_id=1)

        response = self.client.get("/driver/catalog/1")

        self.assertEqual(response.status_code, 403)

    def test_product_detail_escapes_description_html(self):
        self.database_session.execute(
            text("""
                UPDATE catalog_item
                SET description = :description
                WHERE catalog_item_id = 1
            """),
            {"description": "<script>alert('unsafe')</script>"},
        )
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get("/driver/catalog/1")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>", body)

    def test_product_detail_has_description_fallback(self):
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get("/driver/catalog/1")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "No description available.",
            response.get_data(as_text=True),
        )

    def test_catalog_links_to_product_details(self):
        self.sign_in(user_id=101, fake_sponsor_id=2)

        response = self.client.get("/driver/catalog")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/driver/catalog/1"', body)
        self.assertIn('href="/driver/catalog/2"', body)

    def test_product_detail_uses_sponsor_specific_points_conversion(self):
        self.sign_in(user_id=202, fake_sponsor_id=1)

        response = self.client.get("/driver/catalog/4")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "750 points",
            response.get_data(as_text=True),
        )

    def set_balance(self, user_id, balance):
        self.database_session.execute(
            text("""
                UPDATE driver_profile
                SET point_balance = :balance
                WHERE user_id = :user_id
            """),
            {"balance": balance, "user_id": user_id},
        )

    def test_detail_shows_affordable_item_and_remaining_balance(self):
        self.set_balance(101, 1500)
        self.sign_in(user_id=101, fake_sponsor_id=2)

        body = self.client.get("/driver/catalog/1").get_data(as_text=True)

        self.assertIn("Your balance: 1500 points", body)
        self.assertIn("You can afford this item.", body)
        self.assertIn("Balance after purchase: 500 points", body)
        self.assertNotIn("cannot afford", body)

    def test_detail_treats_exact_balance_as_affordable(self):
        self.set_balance(101, 1000)
        self.sign_in(user_id=101, fake_sponsor_id=2)

        body = self.client.get("/driver/catalog/1").get_data(as_text=True)

        self.assertIn("You can afford this item.", body)
        self.assertIn("Balance after purchase: 0 points", body)

    def test_detail_shows_shortfall_when_balance_is_too_low(self):
        self.set_balance(101, 400)
        self.sign_in(user_id=101, fake_sponsor_id=2)

        body = self.client.get("/driver/catalog/1").get_data(as_text=True)

        self.assertIn("Your balance: 400 points", body)
        self.assertIn("You cannot afford this item yet.", body)
        self.assertIn("You need 600 more points.", body)
        self.assertNotIn("You can afford", body)

    def test_detail_handles_zero_balance(self):
        self.sign_in(user_id=101, fake_sponsor_id=2)

        body = self.client.get("/driver/catalog/2").get_data(as_text=True)

        self.assertIn("Your balance: 0 points", body)
        self.assertIn("You need 2000 more points.", body)

    def test_detail_uses_only_the_signed_in_drivers_balance(self):
        self.set_balance(101, 50)
        self.set_balance(202, 9000)
        self.sign_in(user_id=101, fake_sponsor_id=2)

        body = self.client.get("/driver/catalog/1").get_data(as_text=True)

        self.assertIn("Your balance: 50 points", body)
        self.assertNotIn("9000", body)

    def test_detail_affordability_uses_sponsor_conversion_rate(self):
        self.set_balance(202, 750)
        self.sign_in(user_id=202, fake_sponsor_id=1)

        body = self.client.get("/driver/catalog/4").get_data(as_text=True)

        self.assertIn("750 points", body)
        self.assertIn("You can afford this item.", body)

if __name__ == "__main__":
    unittest.main()