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
    v_fqdn := (_rec->>'fqdn');

    -- 1) Upsert into fqdn.
    v_row := public.fqdn_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'fqdn'::citext,
        _natural_key := v_fqdn::citext,
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
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_find_by_content(
    _filters jsonb, 
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS SETOF public.fqdn
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_fqdn   text;
    v_count  integer := 0;
    v_params text[]  := array[]::text[];
    v_sql    text    := 'SELECT * FROM public.fqdn WHERE TRUE';
BEGIN
    -- 1) Extract filters from JSONB
    v_fqdn  := NULLIF(_filters->>'name', '');

    -- 2) Build the params array from the filters
    IF v_fqdn IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_fqdn);
        v_sql    := v_sql || format(' AND %I = $%s', 'fqdn', v_count);
    END IF;

    IF v_count = 0 THEN
        RAISE EXCEPTION 'fqdn_find_by_content requires at least one filter';
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
    END CASE;

    RETURN;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_updated_since(_since timestamp without time zone) 
RETURNS SETOF public.fqdn
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.fqdn
    WHERE updated_at >= _since
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.fqdn_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.fqdn_find_by_content(jsonb, timestamp without time zone);
DROP FUNCTION IF EXISTS public.fqdn_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.fqdn_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.fqdn_upsert(text, jsonb);
DROP FUNCTION IF EXISTS public.fqdn_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_fqdn_updated_at;
DROP INDEX IF EXISTS idx_fqdn_created_at;
DROP TABLE IF EXISTS public.fqdn;