-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Product Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.product (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  unique_id text NOT NULL UNIQUE,
  product_name text NOT NULL,
  product_type text,
  category text,
  product_description text,
  country_of_origin text
);
CREATE INDEX IF NOT EXISTS idx_product_created_at ON public.product(created_at);
CREATE INDEX IF NOT EXISTS idx_product_updated_at ON public.product(updated_at);
CREATE INDEX IF NOT EXISTS idx_product_name ON public.product(product_name);
CREATE INDEX IF NOT EXISTS idx_product_type ON public.product(product_type);
CREATE INDEX IF NOT EXISTS idx_product_category ON public.product(category);
CREATE INDEX IF NOT EXISTS idx_product_description ON public.product(product_description);
CREATE INDEX IF NOT EXISTS idx_product_country_of_origin ON public.product(country_of_origin);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_product_country_of_origin;
DROP INDEX IF EXISTS idx_product_description;
DROP INDEX IF EXISTS idx_product_category;
DROP INDEX IF EXISTS idx_product_type;
DROP INDEX IF EXISTS idx_product_name;
DROP INDEX IF EXISTS idx_product_updated_at;
DROP INDEX IF EXISTS idx_product_created_at;
DROP TABLE IF EXISTS public.product;