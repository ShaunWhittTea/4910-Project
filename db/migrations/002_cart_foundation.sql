-- 002_cart_foundation.sql
-- Target: the current Team09_DB schema containing app_user,
-- driver_profile, sponsor_org, and catalog_item.
--
-- Review with the schema owner before applying to the shared database.
-- Run against a disposable MySQL schema first.
-- No USE statement: the connection must explicitly select the intended schema.

CREATE TABLE cart (
    cart_id BIGINT NOT NULL AUTO_INCREMENT,
    driver_user_id INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (cart_id),
    UNIQUE KEY uq_cart_driver_user (driver_user_id),

    CONSTRAINT fk_cart_driver_user
        FOREIGN KEY (driver_user_id)
        REFERENCES driver_profile (user_id)
        ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE cart_item (
    cart_item_id BIGINT NOT NULL AUTO_INCREMENT,
    cart_id BIGINT NOT NULL,
    catalog_item_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,

    -- Snapshots allow later cart logic to flag changed product prices.
    unit_price_usd_at_add DECIMAL(10,2) NOT NULL,
    unit_points_at_add INT NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (cart_item_id),
    UNIQUE KEY uq_cart_item_product (cart_id, catalog_item_id),
    KEY idx_cart_item_catalog (catalog_item_id),

    CONSTRAINT fk_cart_item_cart
        FOREIGN KEY (cart_id)
        REFERENCES cart (cart_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_cart_item_catalog
        FOREIGN KEY (catalog_item_id)
        REFERENCES catalog_item (catalog_item_id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_cart_item_quantity_positive
        CHECK (quantity > 0),

    CONSTRAINT chk_cart_item_unit_price_nonnegative
        CHECK (unit_price_usd_at_add >= 0),

    CONSTRAINT chk_cart_item_unit_points_nonnegative
        CHECK (unit_points_at_add >= 0)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;