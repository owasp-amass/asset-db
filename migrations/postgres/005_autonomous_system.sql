-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- AutonomousSystem Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.autonomoussystem (
  id         bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  asn        integer NOT NULL UNIQUE,
  attrs      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_autonomoussystem_created_at ON public.autonomoussystem (created_at);
CREATE INDEX IF NOT EXISTS idx_autonomoussystem_updated_at ON public.autonomoussystem (updated_at);

-- Upsert an AutonomousSystem AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_asn integer;
    v_row bigint;
BEGIN
    v_asn := (_rec->>'number')::integer;

    -- 1) Upsert into autonomoussystem by ASN.
    v_row := public.autonomoussystem_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'autonomoussystem'::citext,
        _natural_key := v_asn::text::citext,
        _table_name  := 'public.autonomoussystem'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by ASN (scalar param). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_upsert(
    _asn   integer,
    _attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _asn IS NULL THEN
        RAISE EXCEPTION 'autonomoussystem_upsert requires non-NULL asn';
    END IF;

    INSERT INTO public.autonomoussystem (
        asn, attrs
    ) VALUES (
        _asn, _attrs
    )
    ON CONFLICT (asn) DO UPDATE
    SET
        attrs      = autonomoussystem.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts key: asn. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_asn integer;
BEGIN
    v_asn := NULLIF(_rec->>'number', '')::integer;

    RETURN public.autonomoussystem_upsert(v_asn);
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_get_by_id(_row_id bigint)
RETURNS public.autonomoussystem
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.autonomoussystem
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_find_by_content(
    _filters jsonb, 
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS SETOF TABLE (
    entity_id  bigint,
    id         bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    asn        integer,
    attrs      jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_asn    integer;
    v_count  integer := 0;
    v_params text[]  := array[]::text[];
    v_sql    text;
BEGIN
    v_sql := $Q$
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.asn,
        a.attrs
    FROM public.autonomoussystem a
    JOIN public.entity e ON e.table_name = 'public.autonomoussystem'::citext AND e.row_id = a.id WHERE TRUE$Q$;

    -- 1) Extract filters from JSONB
    v_asn := NULLIF(_filters->>'number', '')::integer;

    -- 2) Build the params array from the filters
    IF v_asn IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_asn::text);
        v_sql    := v_sql || format(' AND %I = $%s', 'a.asn', v_count);
    END IF;

    IF v_count = 0 THEN
        RAISE EXCEPTION 'autonomoussystem_find_by_content requires at least one filter';
    END IF;

    IF _since IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, _since::text);
        v_sql    := v_sql || format(' AND %I >= $%s', 'a.updated_at', v_count);
    END IF;

    -- 3) Add the ORDER BY clause
    v_sql := v_sql || ' ORDER BY a.updated_at DESC, a.id DESC';
    IF _limit > 0 THEN
        v_sql := v_sql || format(' LIMIT %s', _limit);
    END IF;

    -- 4) Execute dynamic SQL and return results
    CASE v_count
        WHEN 1 THEN RETURN QUERY EXECUTE v_sql USING v_params[1];
        WHEN 2 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2];
    END CASE;

    RETURN;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id  bigint,
    id         bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    asn        integer,
    attrs      jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.asn,
        a.attrs
    FROM public.autonomoussystem a
    JOIN public.entity e ON e.table_name = 'public.autonomoussystem'::citext AND e.row_id = a.id
    WHERE a.updated_at >= _since
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT _limit;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.autonomoussystem_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.autonomoussystem_find_by_content(jsonb, timestamp without time zone);
DROP FUNCTION IF EXISTS public.autonomoussystem_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.autonomoussystem_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.autonomoussystem_upsert(integer, jsonb);
DROP FUNCTION IF EXISTS public.autonomoussystem_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_autonomoussystem_updated_at;
DROP INDEX IF EXISTS idx_autonomoussystem_created_at;
DROP TABLE IF EXISTS public.autonomoussystem;