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
CREATE INDEX IF NOT EXISTS idx_product_created_at
  ON public.product(created_at);
CREATE INDEX IF NOT EXISTS idx_product_updated_at
  ON public.product(updated_at);
CREATE INDEX IF NOT EXISTS idx_product_name
  ON public.product(product_name);
CREATE INDEX IF NOT EXISTS idx_product_type
  ON public.product(product_type);
CREATE INDEX IF NOT EXISTS idx_product_category
  ON public.product(category);
CREATE INDEX IF NOT EXISTS idx_product_description
  ON public.product(product_description);
CREATE INDEX IF NOT EXISTS idx_product_country_of_origin
  ON public.product(country_of_origin);

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_upsert(
    _unique_id          text,
    _product_name       text,
    _product_type       text DEFAULT NULL,
    _category           text DEFAULT NULL,
    _product_description text DEFAULT NULL,
    _country_of_origin  text DEFAULT NULL
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
        unique_id,
        product_name,
        product_type,
        category,
        product_description,
        country_of_origin
    ) VALUES (
        _unique_id,
        _product_name,
        _product_type,
        _category,
        _product_description,
        _country_of_origin
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        product_name       = COALESCE(EXCLUDED.product_name,       product.product_name),
        product_type       = COALESCE(EXCLUDED.product_type,       product.product_type),
        category           = COALESCE(EXCLUDED.category,           product.category),
        product_description= COALESCE(EXCLUDED.product_description,product.product_description),
        country_of_origin  = COALESCE(EXCLUDED.country_of_origin,  product.country_of_origin),
        updated_at         = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Accepts keys:
--   unique_id, product_name, product_type, category,
--   product_description, country_of_origin
-- Returns row id.
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
    v_product_description text;
    v_country_of_origin  text;
BEGIN
    v_unique_id           := _rec->>'unique_id';
    v_product_name        := _rec->>'product_name';
    v_product_type        := NULLIF(_rec->>'product_type', '');
    v_category            := NULLIF(_rec->>'category', '');
    v_product_description := NULLIF(_rec->>'product_description', '');
    v_country_of_origin   := NULLIF(_rec->>'country_of_origin', '');

    RETURN public.product_upsert(
        v_unique_id,
        v_product_name,
        v_product_type,
        v_category,
        v_product_description,
        v_country_of_origin
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by unique_id (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_get_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.product
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_get_by_unique_id(
    _unique_id text
) RETURNS public.product
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.product
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by product_name (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_find_by_name(
    _product_name text
) RETURNS SETOF public.product
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.product
    WHERE (CASE
             WHEN strpos(_product_name, '%') > 0 OR strpos(_product_name, '_') > 0
               THEN product_name ILIKE _product_name
             ELSE product_name = _product_name
           END)
    ORDER BY updated_at DESC, id DESC;
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
    SELECT *
    FROM public.product
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a Product AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_upsert_entity(
    _unique_id           text,
    _product_name        text,
    _product_type        text DEFAULT NULL,
    _category            text DEFAULT NULL,
    _product_description text DEFAULT NULL,
    _country_of_origin   text DEFAULT NULL,
    _extra_attrs         jsonb  DEFAULT '{}'::jsonb,        -- caller-provided extra attrs
    _etype_name          citext DEFAULT 'product'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.product%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _unique_id IS NULL OR _product_name IS NULL THEN
        RAISE EXCEPTION 'product_upsert_entity requires non-NULL unique_id and product_name';
    END IF;

    -- 1) Upsert into product by unique_id.
    INSERT INTO public.product (
        unique_id,
        product_name,
        product_type,
        category,
        product_description,
        country_of_origin
    ) VALUES (
        _unique_id,
        _product_name,
        _product_type,
        _category,
        _product_description,
        _country_of_origin
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        product_name        = COALESCE(EXCLUDED.product_name,        product.product_name),
        product_type        = COALESCE(EXCLUDED.product_type,        product.product_type),
        category            = COALESCE(EXCLUDED.category,            product.category),
        product_description = COALESCE(EXCLUDED.product_description, product.product_description),
        country_of_origin   = COALESCE(EXCLUDED.country_of_origin,   product.country_of_origin),
        updated_at          = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the product plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'unique_id',           v_row.unique_id,
            'product_name',        v_row.product_name,
            'product_type',        v_row.product_type,
            'category',            v_row.category,
            'product_description', v_row.product_description,
            'country_of_origin',   v_row.country_of_origin
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using unique_id as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                     -- e.g. 'product'
        _natural_key := v_row.unique_id::citext,         -- canonical key
        _table_name  := 'product'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map unique_id -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_get_entity_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.product p
    JOIN public.entity e
      ON e.table_name = 'product'
     AND e.row_id     = p.id
    WHERE p.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+Product by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_get_with_entity_by_unique_id(
    _unique_id text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    product_row  public.product
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        p
    FROM public.product p
    JOIN public.entity e
      ON e.table_name = 'product'
     AND e.row_id     = p.id
    WHERE p.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.product_upsert(text, text, text, text, text, text);
DROP FUNCTION IF EXISTS public.product_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.product_get_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.product_get_by_unique_id(text);
DROP FUNCTION IF EXISTS public.product_find_by_name(text);
DROP FUNCTION IF EXISTS public.product_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.product_upsert_entity(
    text, text, text, text, text, text, jsonb, citext);
DROP FUNCTION IF EXISTS public.product_get_entity_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.product_get_with_entity_by_unique_id(text);

DROP INDEX IF EXISTS idx_product_country_of_origin;
DROP INDEX IF EXISTS idx_product_description;
DROP INDEX IF EXISTS idx_product_category;
DROP INDEX IF EXISTS idx_product_type;
DROP INDEX IF EXISTS idx_product_name;
DROP INDEX IF EXISTS idx_product_updated_at;
DROP INDEX IF EXISTS idx_product_created_at;
DROP TABLE IF EXISTS public.product;