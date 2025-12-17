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
    SELECT *
    FROM public.product
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_find_by_content(
    _filters jsonb, 
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS SETOF public.product
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_unique_id    text;
    v_product_name text;
    v_product_type text;
    v_count        integer := 0;
    v_params       text[]  := array[]::text[];
    v_sql          text    := 'SELECT * FROM public.product WHERE TRUE';
BEGIN
    -- 1) Extract filters from JSONB
    v_unique_id      := NULLIF(_filters->>'unique_id', '');
    v_product_name   := NULLIF(_filters->>'product_name', '');
    v_product_type   := NULLIF(_filters->>'product_type', '');

    -- 2) Build the params array from the filters
    IF v_unique_id IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_unique_id);
        v_sql    := v_sql || format(' AND %I = $%s', 'unique_id', v_count);
    END IF;

    IF v_product_name IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_product_name);
        v_sql    := v_sql || format(' AND %I = $%s', 'product_name', v_count);
    END IF;

    IF v_product_type IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_product_type);
        v_sql    := v_sql || format(' AND %I = $%s', 'product_type', v_count);
    END IF;

    IF v_count = 0 THEN
        RAISE EXCEPTION 'product_find_by_content requires at least one filter';
    END IF;

    IF _since IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, _since::text);
        v_sql    := v_sql || format(' AND %I >= $%s', 'updated_at', v_count);
    END IF;

    -- 3) Add the ORDER BY clause
    v_sql := v_sql || ' ORDER BY updated_at DESC, id ASC';

    IF _limit > 0 THEN
        v_sql := v_sql || format(' LIMIT %s', _limit);
    END IF;

    -- 4) Execute dynamic SQL and return results
    CASE v_count
        WHEN 1 THEN RETURN QUERY EXECUTE v_sql USING v_params[1];
        WHEN 2 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2];
        WHEN 3 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3];
        WHEN 4 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4];
    END CASE;

    RETURN;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id    bigint,
    id           bigint,
    created_at   timestamp without time zone,
    updated_at   timestamp without time zone,
    unique_id    text,
    product_name text,
    product_type text,
    attrs        jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.unique_id,
        a.product_name,
        a.product_type,
        a.attrs
    FROM public.product a
    JOIN public.entity e ON e.table_name = 'public.product'::citext AND e.row_id = a.id
    WHERE updated_at >= _since
    ORDER BY updated_at DESC, id ASC
    LIMIT _limit;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.product_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.product_find_by_content(jsonb, timestamp without time zone);
DROP FUNCTION IF EXISTS public.product_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.product_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.product_upsert(text, text, text, jsonb);
DROP FUNCTION IF EXISTS public.product_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_product_type;
DROP INDEX IF EXISTS idx_product_name;
DROP INDEX IF EXISTS idx_product_updated_at;
DROP INDEX IF EXISTS idx_product_created_at;
DROP TABLE IF EXISTS public.product;