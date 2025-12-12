-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- ProductRelease Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.productrelease (
  id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at   timestamp without time zone NOT NULL DEFAULT now(),
  updated_at   timestamp without time zone NOT NULL DEFAULT now(),
  release_name text NOT NULL UNIQUE,
  attrs        jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_productrelease_created_at ON public.productrelease (created_at);
CREATE INDEX IF NOT EXISTS idx_productrelease_updated_at ON public.productrelease (updated_at);

-- Upsert a ProductRelease AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_name text;
    v_row  bigint;
BEGIN
    v_name := (_rec->>'name');

    -- 1) Upsert into productrelease.
    v_row := public.productrelease_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'productrelease'::citext,
        _natural_key := v_name::citext,
        _table_name  := 'public.productrelease'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by release_name (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_upsert(
    _release_name text,
    _attrs        jsonb DEFAULT '{}'::jsonb
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
        release_name, attrs
    ) VALUES (
        _release_name, _attrs
    )
    ON CONFLICT (release_name) DO UPDATE
    SET
        attrs        = productrelease.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_name         text;
    v_attrs        jsonb;
    v_release_date timestamp without time zone;
BEGIN
    v_name         := NULLIF(_rec->>'name', '');
    v_release_date := NULLIF(_rec->>'release_date', '')::timestamp;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'release_date', v_release_date
        )
    ) || '{}'::jsonb;

    RETURN public.productrelease_upsert(
        v_name,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_get_by_id(_row_id bigint)
RETURNS public.productrelease
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, release_name, attrs
    FROM public.productrelease
    WHERE id = _row_id
    LIMIT 1;
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
    SELECT id, created_at, updated_at, release_name, attrs
    FROM public.productrelease
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.productrelease_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.productrelease_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.productrelease_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.productrelease_upsert(text, jsonb);
DROP FUNCTION IF EXISTS public.productrelease_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_productrelease_updated_at;
DROP INDEX IF EXISTS idx_productrelease_created_at;
DROP TABLE IF EXISTS public.productrelease;