-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- ProductRelease Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.productrelease (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  release_name text NOT NULL UNIQUE,
  release_date timestamp without time zone
);
CREATE INDEX IF NOT EXISTS idx_productrelease_created_at
  ON public.productrelease(created_at);
CREATE INDEX IF NOT EXISTS idx_productrelease_updated_at
  ON public.productrelease(updated_at);

-- Upsert by release_name (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_upsert(
    _release_name text,
    _release_date timestamp without time zone DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _release_name IS NULL THEN
        RAISE EXCEPTION 'productrelease_upsert requires non-NULL release_name';
    END IF;

    INSERT INTO public.productrelease (
        release_name,
        release_date
    ) VALUES (
        _release_name,
        _release_date
    )
    ON CONFLICT (release_name) DO UPDATE
    SET
        release_date = COALESCE(EXCLUDED.release_date, productrelease.release_date),
        updated_at   = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Accepts keys:
--   release_name, release_date
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_release_name text;
    v_release_date timestamp without time zone;
BEGIN
    v_release_name := _rec->>'release_name';
    v_release_date := NULLIF(_rec->>'release_date', '')::timestamp;

    RETURN public.productrelease_upsert(
        v_release_name,
        v_release_date
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by release_name (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_get_id_by_release_name(
    _release_name text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.productrelease
    WHERE release_name = _release_name
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by release_name
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_get_by_release_name(
    _release_name text
) RETURNS public.productrelease
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.productrelease
    WHERE release_name = _release_name
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by release_name (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_find_by_release_name(
    _release_name text
) RETURNS SETOF public.productrelease
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.productrelease
    WHERE (CASE
             WHEN strpos(_release_name, '%') > 0 OR strpos(_release_name, '_') > 0
               THEN release_name ILIKE _release_name
             ELSE release_name = _release_name
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.productrelease
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.productrelease
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a ProductRelease AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_upsert_entity(
    _release_name text,
    _release_date timestamp without time zone DEFAULT NULL,
    _extra_attrs  jsonb  DEFAULT '{}'::jsonb,        -- caller-provided extra attrs
    _etype_name   citext DEFAULT 'productrelease'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.productrelease%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _release_name IS NULL THEN
        RAISE EXCEPTION 'productrelease_upsert_entity requires non-NULL release_name';
    END IF;

    -- 1) Upsert into productrelease by release_name.
    INSERT INTO public.productrelease (
        release_name,
        release_date
    ) VALUES (
        _release_name,
        _release_date
    )
    ON CONFLICT (release_name) DO UPDATE
    SET
        release_date = COALESCE(EXCLUDED.release_date, productrelease.release_date),
        updated_at   = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the productrelease plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'release_name', v_row.release_name,
            'release_date', v_row.release_date
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using release_name as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                       -- e.g. 'productrelease'
        _natural_key := v_row.release_name::citext,        -- canonical key
        _table_name  := 'productrelease'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map release_name -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_get_entity_id_by_release_name(
    _release_name text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.productrelease pr
    JOIN public.entity e
      ON e.table_name = 'productrelease'
     AND e.row_id     = pr.id
    WHERE pr.release_name = _release_name
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+ProductRelease by release_name
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_get_with_entity_by_release_name(
    _release_name text
) RETURNS TABLE (
    entity_id     bigint,
    etype_id      smallint,
    natural_key   citext,
    entity_attrs  jsonb,
    release_row   public.productrelease
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        pr
    FROM public.productrelease pr
    JOIN public.entity e
      ON e.table_name = 'productrelease'
     AND e.row_id     = pr.id
    WHERE pr.release_name = _release_name
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.productrelease_upsert(
    text,
    timestamp without time zone
);
DROP FUNCTION IF EXISTS public.productrelease_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.productrelease_get_id_by_release_name(text);
DROP FUNCTION IF EXISTS public.productrelease_get_by_release_name(text);
DROP FUNCTION IF EXISTS public.productrelease_find_by_release_name(text);
DROP FUNCTION IF EXISTS public.productrelease_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.productrelease_upsert_entity(
    text,
    timestamp without time zone,
    jsonb,
    citext
);
DROP FUNCTION IF EXISTS public.productrelease_get_entity_id_by_release_name(text);
DROP FUNCTION IF EXISTS public.productrelease_get_with_entity_by_release_name(text);

DROP INDEX IF EXISTS idx_productrelease_updated_at;
DROP INDEX IF EXISTS idx_productrelease_created_at;
DROP TABLE IF EXISTS public.productrelease;