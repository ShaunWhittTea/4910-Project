import os
import unittest
from dataclasses import replace
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-database")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import app as sponsor_app
from product_api import EbayApiError, ExternalProduct

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
    status TEXT NOT NULL,
    sponsor_org_id INTEGER
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
    active INTEGER NOT NULL,
    last_synced_at TEXT,
    UNIQUE (sponsor_org_id, external_product_id)
);
"""


def sample_product(**overrides):
    product = ExternalProduct(
        external_product_id="v1|111|0",
        title="Travel Thermos",
        description="Keeps drinks hot.",
        price_usd=19.99,
        image_url="https://img.example/thermos.jpg",
        availability="AVAILABLE",
    )
    return replace(product, **overrides)


class SponsorCatalogTests(unittest.TestCase):
    def setUp(self):
        sponsor_app.app.config.update(
            TESTING=True, SECRET_KEY="test-secret-key"
        )
        self.context = sponsor_app.app.app_context()
        self.context.push()

        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        with self.engine.begin() as connection:
            for statement in SCHEMA.strip().split(";"):
                if statement.strip():
                    connection.execute(text(statement))
            connection.execute(text("""
                INSERT INTO sponsor_org
                    (sponsor_org_id, name, point_dollar_value, status)
                VALUES (1, 'Sponsor A', 0.01, 'ACTIVE'),
                       (2, 'Sponsor B', 0.01, 'ACTIVE')
            """))
            connection.execute(text("""
                INSERT INTO app_user
                    (user_id, role, status, sponsor_org_id)
                VALUES (11, 'SPONSOR', 'ACTIVE', 1),
                       (22, 'SPONSOR', 'ACTIVE', 2),
                       (33, 'SPONSOR', 'INACTIVE', 1),
                       (44, 'DRIVER', 'ACTIVE', NULL)
            """))

        self.database_session = Session(self.engine)
        db_session = sponsor_app.db.session
        self.patches = [
            patch.object(
                db_session, "execute",
                side_effect=self.database_session.execute,
            ),
            patch.object(
                db_session, "commit",
                side_effect=self.database_session.commit,
            ),
            patch.object(
                db_session, "rollback",
                side_effect=self.database_session.rollback,
            ),
        ]
        for active_patch in self.patches:
            active_patch.start()

        self.provider_patch = patch.object(
            sponsor_app, "get_product_search_client"
        )
        self.get_provider = self.provider_patch.start()
        self.provider = self.get_provider.return_value
        self.provider.get_by_external_id.return_value = sample_product()

        self.client = sponsor_app.app.test_client()

    def tearDown(self):
        self.provider_patch.stop()
        for active_patch in self.patches:
            active_patch.stop()
        self.database_session.close()
        self.engine.dispose()
        sponsor_app.db.session.remove()
        self.context.pop()

    def sign_in(self, user_id, role="SPONSOR", fake_org=999):
        with self.client.session_transaction() as login_session:
            login_session.clear()
            login_session["user_id"] = user_id
            login_session["role"] = role
            login_session["sponsor_org_id"] = fake_org

    def flashes(self):
        with self.client.session_transaction() as login_session:
            return [message for _, message in login_session.get("_flashes", [])]

    def post_add(self, **form):
        data = {"external_product_id": "v1|111|0", "q": "thermos"}
        data.update(form)
        return self.client.post("/sponsor/products/add", data=data)

    def insert_item(self, item_id, org, external_id, title, price, active=1):
        self.database_session.execute(
            text("""
                INSERT INTO catalog_item (
                    catalog_item_id, sponsor_org_id, external_product_id,
                    title, price_usd, active
                )
                VALUES (:id, :org, :ext, :title, :price, :active)
            """),
            {"id": item_id, "org": org, "ext": external_id,
             "title": title, "price": price, "active": active},
        )
        self.database_session.commit()

    def rows(self):
        return self.database_session.execute(
            text("SELECT * FROM catalog_item ORDER BY catalog_item_id")
        ).mappings().all()

    # --- access control -------------------------------------------------

    def test_guest_and_driver_cannot_add_or_remove(self):
        response = self.post_add()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/login"))

        response = self.client.post("/sponsor/catalog/1/remove")
        self.assertEqual(response.status_code, 302)

        self.sign_in(44, role="DRIVER")
        self.assertEqual(self.post_add().status_code, 403)
        self.assertEqual(
            self.client.post("/sponsor/catalog/1/remove").status_code, 403
        )
        self.get_provider.assert_not_called()
        self.assertEqual(self.rows(), [])

    def test_inactive_sponsor_cannot_add(self):
        self.sign_in(33)

        response = self.post_add()

        self.assertEqual(response.status_code, 403)
        self.provider.get_by_external_id.assert_not_called()
        self.assertEqual(self.rows(), [])

    # --- add ------------------------------------------------------------

    def test_add_uses_provider_data_and_database_sponsor(self):
        self.sign_in(11, fake_org=2)

        response = self.post_add(
            title="Hacked title", price_usd="0.01", sponsor_org_id="2"
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/sponsor/products/search", response.location)
        self.assertIn("q=thermos", response.location)

        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sponsor_org_id"], 1)
        self.assertEqual(rows[0]["title"], "Travel Thermos")
        self.assertEqual(float(rows[0]["price_usd"]), 19.99)
        self.assertEqual(rows[0]["active"], 1)
        self.assertIsNotNone(rows[0]["last_synced_at"])
        self.provider.get_by_external_id.assert_called_once_with("v1|111|0")
        self.assertIn("was added", self.flashes()[0])

    def test_duplicate_active_product_is_not_added_twice(self):
        self.sign_in(11)
        self.assertEqual(self.post_add().status_code, 302)

        self.post_add()

        self.assertEqual(len(self.rows()), 1)
        self.assertIn("already in your catalog", self.flashes()[-1])

    def test_removed_product_is_reactivated_with_fresh_data(self):
        self.insert_item(5, 1, "v1|111|0", "Old title", 5.00, active=0)
        self.provider.get_by_external_id.return_value = sample_product(
            title="New title", price_usd=21.5
        )
        self.sign_in(11)

        self.post_add()

        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["active"], 1)
        self.assertEqual(rows[0]["title"], "New title")
        self.assertEqual(float(rows[0]["price_usd"]), 21.5)

    def test_same_external_product_can_be_in_two_sponsor_catalogs(self):
        self.sign_in(11)
        self.post_add()
        self.sign_in(22)
        self.post_add()

        self.assertEqual(
            sorted(row["sponsor_org_id"] for row in self.rows()), [1, 2]
        )

    def test_unavailable_and_invalid_products_are_rejected(self):
        self.sign_in(11)
        bad_products = [
            sample_product(availability="UNAVAILABLE"),
            sample_product(price_usd=0),
            sample_product(price_usd=float("inf")),
            sample_product(title="   "),
        ]

        for product in bad_products:
            with self.subTest(product=product):
                self.provider.get_by_external_id.return_value = product
                response = self.post_add()
                self.assertEqual(response.status_code, 302)

        self.assertEqual(self.rows(), [])

    def test_missing_product_and_provider_failure_add_nothing(self):
        self.sign_in(11)

        self.provider.get_by_external_id.return_value = None
        self.post_add()
        self.assertIn("could not be found", self.flashes()[-1])

        self.provider.get_by_external_id.side_effect = EbayApiError("down")
        self.post_add()
        self.assertIn("unavailable", self.flashes()[-1])

        self.assertEqual(self.rows(), [])

    def test_invalid_external_ids_do_not_call_provider(self):
        self.sign_in(11)

        for external_id in ("", "   ", "x" * 121):
            with self.subTest(external_id=external_id):
                self.post_add(external_product_id=external_id)

        self.provider.get_by_external_id.assert_not_called()
        self.assertEqual(self.rows(), [])

    # --- list and remove ------------------------------------------------

    def test_catalog_list_shows_only_own_active_items(self):
        self.insert_item(1, 1, "a-1", "Alpha Thermos", 10)
        self.insert_item(2, 1, "a-2", "Hidden Item", 10, active=0)
        self.insert_item(3, 2, "b-1", "Other Sponsor Item", 10)
        self.sign_in(11)

        response = self.client.get("/sponsor/catalog")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Alpha Thermos", body)
        self.assertNotIn("Hidden Item", body)
        self.assertNotIn("Other Sponsor Item", body)

    def test_sponsor_can_remove_own_item(self):
        self.insert_item(1, 1, "a-1", "Alpha Thermos", 10)
        self.sign_in(11)

        response = self.client.post("/sponsor/catalog/1/remove")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/sponsor/catalog"))
        self.assertEqual(self.rows()[0]["active"], 0)
        self.assertIn("removed", self.flashes()[0])

    def test_sponsor_cannot_remove_another_sponsors_or_inactive_item(self):
        self.insert_item(1, 1, "a-1", "Own Inactive", 10, active=0)
        self.insert_item(2, 2, "b-1", "Other Sponsor", 10)
        self.sign_in(11)

        for item_id in (1, 2, 999):
            with self.subTest(item_id=item_id):
                response = self.client.post(
                    f"/sponsor/catalog/{item_id}/remove"
                )
                self.assertEqual(response.status_code, 404)

        by_id = {row["catalog_item_id"]: row["active"] for row in self.rows()}
        self.assertEqual(by_id, {1: 0, 2: 1})


if __name__ == "__main__":
    unittest.main()