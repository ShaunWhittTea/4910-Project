USE Team09_DB;

ALTER TABLE driver_profile
  ADD COLUMN point_alerts_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN order_alerts_enabled BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE driver_sponsor_membership (
  driver_user_id  INT NOT NULL,
  sponsor_org_id  INT NOT NULL,
  status          ENUM('ACTIVE','REMOVED') NOT NULL DEFAULT 'ACTIVE',
  point_balance   INT NOT NULL DEFAULT 0,
  joined_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (driver_user_id, sponsor_org_id),
  CONSTRAINT fk_membership_driver FOREIGN KEY (driver_user_id)
    REFERENCES app_user(user_id) ON DELETE CASCADE,
  CONSTRAINT fk_membership_org FOREIGN KEY (sponsor_org_id)
    REFERENCES sponsor_org(sponsor_org_id),
  CONSTRAINT chk_membership_balance_nonneg CHECK (point_balance >= 0)
);

CREATE INDEX idx_membership_org_status
  ON driver_sponsor_membership(sponsor_org_id, status);

INSERT INTO driver_sponsor_membership
    (driver_user_id, sponsor_org_id, status, point_balance)
SELECT user_id, sponsor_org_id, 'ACTIVE', point_balance
FROM driver_profile
WHERE sponsor_org_id IS NOT NULL;

CREATE TABLE driver_notification (
  notification_id  BIGINT AUTO_INCREMENT PRIMARY KEY,
  driver_user_id   INT NOT NULL,
  sponsor_org_id   INT NULL,
  notification_type ENUM('POINT_CHANGE','ORDER_SUMMARY','SPONSOR_REMOVAL')
                      NOT NULL,
  title            VARCHAR(160) NOT NULL,
  message          VARCHAR(1000) NOT NULL,
  created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  read_at          TIMESTAMP NULL,
  CONSTRAINT fk_notification_driver FOREIGN KEY (driver_user_id)
    REFERENCES app_user(user_id) ON DELETE CASCADE,
  CONSTRAINT fk_notification_org FOREIGN KEY (sponsor_org_id)
    REFERENCES sponsor_org(sponsor_org_id)
);

CREATE INDEX idx_notification_driver_time
  ON driver_notification(driver_user_id, created_at);
