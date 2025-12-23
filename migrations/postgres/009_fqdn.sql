-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- FQDN Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.fqdn (
  id         bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  fqdn       citext NOT NULL UNIQUE,
  attrs      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_fqdn_created_at ON public.fqdn (created_at);
CREATE INDEX IF NOT EXISTS idx_fqdn_updated_at ON public.fqdn (updated_at);

-- Upsert an FQDN AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_fqdn text;
    v_row  bigint;
BEGIN
    v_fqdn := NULLIF(_rec->>'name', '');

    -- 1) Upsert into fqdn.
    v_row := public.fqdn_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'fqdn'::citext,
        _natural_key := lower(v_fqdn)::citext,
        _table_name  := 'public.fqdn'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by FQDN (scalar param). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_upsert(
    _fqdn  text,
    _attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _fqdn IS NULL THEN
        RAISE EXCEPTION 'fqdn_upsert requires non-NULL fqdn';
    END IF;

    INSERT INTO public.fqdn (
        fqdn, attrs
    ) VALUES (
        lower(_fqdn)::citext, _attrs
    )
    ON CONFLICT (fqdn) DO UPDATE
    SET
        attrs      = fqdn.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts key: fqdn. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_fqdn text;
BEGIN
    v_fqdn := NULLIF(_rec->>'name', '');

    RETURN public.fqdn_upsert(v_fqdn);
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_get_by_id(_row_id bigint)
RETURNS public.fqdn
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.fqdn
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: fqdn (preferred) or name (compat).
-- Requires at least one supported filter to be present.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS TABLE (
    entity_id  bigint,
    id         bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    fqdn       citext,
    attrs      jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    WITH f AS (
        SELECT
            lower(
              COALESCE(
                NULLIF(_filters->>'fqdn',''),
                NULLIF(_filters->>'name','')
              )
            )::citext AS fqdn,
            _since AS since_ts,
            GREATEST(COALESCE(_limit, 0), 0) AS lim
    )
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.fqdn,
        a.attrs
    FROM public.fqdn a
    JOIN public.entity e ON e.table_name = 'public.fqdn'::citext AND e.row_id = a.id
    CROSS JOIN f
    WHERE
        -- require at least one supported filter
        (f.fqdn IS NOT NULL)
      AND (a.fqdn = f.fqdn)
      AND (f.since_ts IS NULL OR a.updated_at >= f.since_ts)
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT CASE WHEN (SELECT lim FROM f) > 0 THEN (SELECT lim FROM f) ELSE ALL END;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT 0
) RETURNS TABLE (
    entity_id  bigint,
    id         bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    fqdn       citext,
    attrs      jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    WITH p AS (
        SELECT GREATEST(COALESCE(_limit, 0), 0) AS lim
    )
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.fqdn,
        a.attrs
    FROM public.fqdn a
    JOIN public.entity e ON e.table_name = 'public.fqdn'::citext AND e.row_id = a.id
    CROSS JOIN p
    WHERE a.updated_at >= _since
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT CASE WHEN (SELECT lim FROM p) > 0 THEN (SELECT lim FROM p) ELSE ALL END;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.fqdn_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.fqdn_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.fqdn_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.fqdn_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.fqdn_upsert(text, jsonb);
DROP FUNCTION IF EXISTS public.fqdn_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_fqdn_updated_at;
DROP INDEX IF EXISTS idx_fqdn_created_at;
DROP TABLE IF EXISTS public.fqdn;