-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Product Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.product (
  id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at   timestamp without time zone NOT NULL DEFAULT now(),
  updated_at   timestamp without time zone NOT NULL DEFAULT now(),
  unique_id    text NOT NULL UNIQUE,
  product_name text NOT NULL,
  product_type text,
  attrs        jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_product_created_at ON public.product (created_at);
CREATE INDEX IF NOT EXISTS idx_product_updated_at ON public.product (updated_at);
CREATE INDEX IF NOT EXISTS idx_product_name ON public.product (product_name);
CREATE INDEX IF NOT EXISTS idx_product_type ON public.product (product_type);

-- Upsert a Product AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id text;
    v_row       bigint;
BEGIN
    v_unique_id := (_rec->>'unique_id');

    -- 1) Upsert into product.
    v_row := public.product_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'product'::citext,
        _natural_key := v_unique_id::citext,
        _table_name  := 'public.product'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_upsert(
    _unique_id    text,
    _product_name text,
    _product_type text DEFAULT NULL,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _product_name IS NULL THEN
        RAISE EXCEPTION 'product_upsert requires non-NULL unique_id and product_name';
    END IF;

    INSERT INTO public.product (
        unique_id, product_name, product_type, attrs
    ) VALUES (
        _unique_id, _product_name, _product_type, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        product_name = COALESCE(EXCLUDED.product_name, product.product_name),
        product_type = COALESCE(EXCLUDED.product_type, product.product_type),
        attrs        = product.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id          text;
    v_product_name       text;
    v_product_type       text;
    v_category           text;
    v_description        text;
    v_country_of_origin  text;
    v_attrs              jsonb;
BEGIN
    v_unique_id           := NULLIF(_rec->>'unique_id', '');
    v_product_name        := NULLIF(_rec->>'product_name', '');
    v_product_type        := NULLIF(_rec->>'product_type', '');
    v_category            := NULLIF(_rec->>'category', '');
    v_description         := NULLIF(_rec->>'description', '');
    v_country_of_origin   := NULLIF(_rec->>'country_of_origin', '');

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'category',          v_category,
            'description',       v_description,
            'country_of_origin', v_country_of_origin
        )
    ) || '{}'::jsonb;

    RETURN public.product_upsert(
        v_unique_id,
        v_product_name,
        v_product_type,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_get_by_id(_row_id bigint)
RETURNS public.product
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, unique_id, product_name, product_type, attrs
    FROM public.product
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.product
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, unique_id, product_name, product_type, attrs
    FROM public.product
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.product_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.product_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.product_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.product_upsert(text, text, text, jsonb);
DROP FUNCTION IF EXISTS public.product_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_product_type;
DROP INDEX IF EXISTS idx_product_name;
DROP INDEX IF EXISTS idx_product_updated_at;
DROP INDEX IF EXISTS idx_product_created_at;
DROP TABLE IF EXISTS public.product;