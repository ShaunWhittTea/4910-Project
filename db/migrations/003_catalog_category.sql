-- 003_catalog_category.sql
-- Add category support to the existing catalog_item table.
--
-- Test against team09_cart_test first.
-- Review with the schema owner before applying to Team09_DB.
-- No USE statement: explicitly select the intended schema.
-- Run once per schema.

ALTER TABLE catalog_item
    ADD COLUMN category VARCHAR(120) NULL AFTER description,
    ADD INDEX idx_catalog_org_active_category
        (sponsor_org_id, active, category);