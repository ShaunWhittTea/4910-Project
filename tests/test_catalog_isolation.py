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
    sponsor_org_id INTEGER NOT NULL
);

CREATE TABLE catalog_item (
    catalog_item_id INTEGER PRIMARY KEY,
    sponsor_org_id INTEGER NOT NULL,
    external_product_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
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

    def test_inactive_driver_receives_no_catalog_rows(self):
        self.sign_in(user_id=303, fake_sponsor_id=1)

        response = self.client.get("/api/catalog/items")

        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()