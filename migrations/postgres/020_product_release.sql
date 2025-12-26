-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- ProductRelease Table native for asset type
-- ============================================================================


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
    v_name := NULLIF(_rec->>'name', '');

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
    v_release_date date;
BEGIN
    v_name         := NULLIF(_rec->>'name', '');
    v_release_date := NULLIF(_rec->>'release_date', '')::date;

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
    SELECT *
    FROM public.productrelease
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: name
-- Requires at least one supported filter to be present.
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT NULL
) RETURNS TABLE (
    entity_id    bigint,
    id           bigint,
    created_at   timestamp without time zone,
    updated_at   timestamp without time zone,
    release_name text,
    attrs        jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_name  text    := NULLIF(_filters->>'name', '');
    v_limit integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    IF v_name IS NULL THEN
        RAISE EXCEPTION 'productrelease_find_by_content requires at least one filter';
    END IF;

    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.release_name,
            a.attrs
        FROM public.productrelease a
        JOIN public.entity e ON e.table_name = 'public.productrelease'::citext AND e.row_id = a.id
        WHERE a.release_name = v_name AND (_since IS NULL OR a.updated_at >= _since)
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.release_name,
            a.attrs
        FROM public.productrelease a
        JOIN public.entity e ON e.table_name = 'public.productrelease'::citext AND e.row_id = a.id
        WHERE a.release_name = v_name AND (_since IS NULL OR a.updated_at >= _since)
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id    bigint,
    id           bigint,
    created_at   timestamp without time zone,
    updated_at   timestamp without time zone,
    release_name text,
    attrs        jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_limit integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.release_name,
            a.attrs
        FROM public.productrelease a
        JOIN public.entity e ON e.table_name = 'public.productrelease'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.release_name,
            a.attrs
        FROM public.productrelease a
        JOIN public.entity e ON e.table_name = 'public.productrelease'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd


-- +migrate Down

DROP FUNCTION IF EXISTS public.productrelease_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.productrelease_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.productrelease_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.productrelease_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.productrelease_upsert(text, jsonb);
DROP FUNCTION IF EXISTS public.productrelease_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_productrelease_updated_at;
DROP INDEX IF EXISTS idx_productrelease_created_at;
DROP TABLE IF EXISTS public.productrelease;