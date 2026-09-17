-- Good Driver Incentive Program — starting schema (MySQL 8)
-- Scope: enough tables to exercise the admin / audit / reporting endpoints.
-- Catalog and order tables are included because the sales reports and the 1% fee
-- calculation depend on them.

CREATE DATABASE IF NOT EXISTS Incentive
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE Incentive;

-- ---------------------------------------------------------------------------
-- Organizations
-- ---------------------------------------------------------------------------
CREATE TABLE sponsor_org (
  sponsor_org_id      INT AUTO_INCREMENT PRIMARY KEY,
  name                VARCHAR(120)  NOT NULL UNIQUE,
  contact_email       VARCHAR(255)  NOT NULL,
  phone               VARCHAR(40),
  -- dollars that one point is worth; slide 10 default is $0.01
  point_dollar_value  DECIMAL(10,4) NOT NULL DEFAULT 0.0100,
  status              ENUM('ACTIVE','SUSPENDED') NOT NULL DEFAULT 'ACTIVE',
  created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- Users. One table, discriminated by role, so login does not require the user
-- to declare their type (slide 18).
-- ---------------------------------------------------------------------------
CREATE TABLE app_user (
  user_id         INT AUTO_INCREMENT PRIMARY KEY,
  role            ENUM('DRIVER','SPONSOR','ADMIN') NOT NULL,
  email           VARCHAR(255) NOT NULL UNIQUE,
  password_hash   VARCHAR(255),              -- NULL until first activation
  first_name      VARCHAR(80)  NOT NULL,
  last_name       VARCHAR(80)  NOT NULL,
  phone           VARCHAR(40),
  status          ENUM('PENDING','ACTIVE','INACTIVE') NOT NULL DEFAULT 'PENDING',
  -- populated for SPONSOR users; NULL for ADMIN
  sponsor_org_id  INT NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_user_org FOREIGN KEY (sponsor_org_id)
    REFERENCES sponsor_org(sponsor_org_id)
);
CREATE INDEX idx_user_role ON app_user(role);
CREATE INDEX idx_user_org  ON app_user(sponsor_org_id);

-- Driver-specific fields. The 1:1 with sponsor_org enforces "one sponsor per
-- driver" (slide 8) at the schema level.
CREATE TABLE driver_profile (
  user_id           INT PRIMARY KEY,
  sponsor_org_id    INT NOT NULL,
  point_balance     INT NOT NULL DEFAULT 0,
  shipping_address  VARCHAR(400),
  CONSTRAINT fk_driver_user FOREIGN KEY (user_id)
    REFERENCES app_user(user_id) ON DELETE CASCADE,
  CONSTRAINT fk_driver_org FOREIGN KEY (sponsor_org_id)
    REFERENCES sponsor_org(sponsor_org_id),
  CONSTRAINT chk_balance_nonneg CHECK (point_balance >= 0)
);

-- ---------------------------------------------------------------------------
-- Driver applications
-- ---------------------------------------------------------------------------
CREATE TABLE driver_application (
  application_id  INT AUTO_INCREMENT PRIMARY KEY,
  driver_user_id  INT NOT NULL,
  sponsor_org_id  INT NOT NULL,
  status          ENUM('PENDING','APPROVED','REJECTED','REVOKED')
                    NOT NULL DEFAULT 'PENDING',
  reason          VARCHAR(500),
  decided_by      INT NULL,
  decided_at      TIMESTAMP NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_app_driver FOREIGN KEY (driver_user_id) REFERENCES app_user(user_id),
  CONSTRAINT fk_app_org    FOREIGN KEY (sponsor_org_id) REFERENCES sponsor_org(sponsor_org_id),
  CONSTRAINT fk_app_actor  FOREIGN KEY (decided_by)     REFERENCES app_user(user_id)
);
CREATE INDEX idx_app_created ON driver_application(created_at);

-- ---------------------------------------------------------------------------
-- Point ledger. Signed values; the sum for a driver must equal point_balance.
-- That invariant is worth an automated test (INF-03 / AUD-02).
-- ---------------------------------------------------------------------------
CREATE TABLE point_change (
  point_change_id  BIGINT AUTO_INCREMENT PRIMARY KEY,
  driver_user_id   INT NOT NULL,
  sponsor_org_id   INT NOT NULL,
  actor_user_id    INT NULL,             -- NULL = system/automated award
  points           INT NOT NULL,         -- negative for deductions
  reason           VARCHAR(500) NOT NULL,
  created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_pc_driver FOREIGN KEY (driver_user_id) REFERENCES app_user(user_id),
  CONSTRAINT fk_pc_org    FOREIGN KEY (sponsor_org_id) REFERENCES sponsor_org(sponsor_org_id),
  CONSTRAINT fk_pc_actor  FOREIGN KEY (actor_user_id)  REFERENCES app_user(user_id)
);
CREATE INDEX idx_pc_driver_date ON point_change(driver_user_id, created_at);
CREATE INDEX idx_pc_org_date    ON point_change(sponsor_org_id, created_at);

-- ---------------------------------------------------------------------------
-- Catalog. Products originate from the external web API, so we cache the
-- external id plus a snapshot of price/description.
-- ---------------------------------------------------------------------------
CREATE TABLE catalog_item (
  catalog_item_id      INT AUTO_INCREMENT PRIMARY KEY,
  sponsor_org_id       INT NOT NULL,
  external_product_id  VARCHAR(120) NOT NULL,
  title                VARCHAR(300) NOT NULL,
  description          TEXT,
  price_usd            DECIMAL(10,2) NOT NULL,
  image_url            VARCHAR(1000),
  active               BOOLEAN NOT NULL DEFAULT TRUE,
  last_synced_at       TIMESTAMP NULL,
  CONSTRAINT fk_cat_org FOREIGN KEY (sponsor_org_id) REFERENCES sponsor_org(sponsor_org_id),
  CONSTRAINT uq_cat_org_product UNIQUE (sponsor_org_id, external_product_id)
);

-- ---------------------------------------------------------------------------
-- Orders. total_usd is the basis for the sales reports and the 1% invoice.
-- Prices are snapshotted at order time so later catalog changes do not
-- retroactively alter historical revenue.
-- ---------------------------------------------------------------------------
CREATE TABLE purchase_order (
  order_id           BIGINT AUTO_INCREMENT PRIMARY KEY,
  driver_user_id     INT NOT NULL,
  sponsor_org_id     INT NOT NULL,
  placed_by_user_id  INT NOT NULL,       -- driver, or sponsor acting as help desk
  status             ENUM('PLACED','CANCELLED','SHIPPED','DELIVERED')
                       NOT NULL DEFAULT 'PLACED',
  total_points       INT NOT NULL,
  total_usd          DECIMAL(12,2) NOT NULL,
  created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_ord_driver FOREIGN KEY (driver_user_id)    REFERENCES app_user(user_id),
  CONSTRAINT fk_ord_org    FOREIGN KEY (sponsor_org_id)    REFERENCES sponsor_org(sponsor_org_id),
  CONSTRAINT fk_ord_placer FOREIGN KEY (placed_by_user_id) REFERENCES app_user(user_id)
);
CREATE INDEX idx_ord_org_date    ON purchase_order(sponsor_org_id, created_at);
CREATE INDEX idx_ord_driver_date ON purchase_order(driver_user_id, created_at);

CREATE TABLE order_line (
  order_line_id        BIGINT AUTO_INCREMENT PRIMARY KEY,
  order_id             BIGINT NOT NULL,
  external_product_id  VARCHAR(120) NOT NULL,
  title                VARCHAR(300) NOT NULL,
  quantity             INT NOT NULL,
  unit_price_usd       DECIMAL(10,2) NOT NULL,
  unit_points          INT NOT NULL,
  CONSTRAINT fk_line_order FOREIGN KEY (order_id)
    REFERENCES purchase_order(order_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Audit log. Append-only: grant the application DB user INSERT and SELECT on
-- this table, but not UPDATE or DELETE (AUD-08).
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
  audit_id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  category            ENUM('APPLICATION','POINT_CHANGE','PASSWORD_CHANGE',
                           'LOGIN_ATTEMPT','ACCOUNT','IMPERSONATION','ORDER')
                        NOT NULL,
  event_time          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- store UTC
  actor_user_id       INT NULL,
  target_user_id      INT NULL,
  sponsor_org_id      INT NULL,
  username_attempted  VARCHAR(255) NULL,   -- login attempts for unknown users
  success             BOOLEAN NULL,
  reason              VARCHAR(500) NULL,
  detail              JSON NULL,           -- never store secrets here (AUD-10)
  CONSTRAINT fk_audit_actor  FOREIGN KEY (actor_user_id)  REFERENCES app_user(user_id),
  CONSTRAINT fk_audit_target FOREIGN KEY (target_user_id) REFERENCES app_user(user_id),
  CONSTRAINT fk_audit_org    FOREIGN KEY (sponsor_org_id) REFERENCES sponsor_org(sponsor_org_id)
);
CREATE INDEX idx_audit_cat_time ON audit_log(category, event_time);
CREATE INDEX idx_audit_org_time ON audit_log(sponsor_org_id, event_time);

-- ---------------------------------------------------------------------------
-- About page data (slide 17). Update the row each sprint.
-- ---------------------------------------------------------------------------
CREATE TABLE about_info (
  about_id             INT AUTO_INCREMENT PRIMARY KEY,
  team_number          VARCHAR(20)  NOT NULL,
  version_number       VARCHAR(20)  NOT NULL,
  release_date         DATE         NOT NULL,
  product_name         VARCHAR(200) NOT NULL,
  product_description  TEXT         NOT NULL,
  updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                         ON UPDATE CURRENT_TIMESTAMP
);
