-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Organization Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.organization (
  id              bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at      timestamp without time zone NOT NULL DEFAULT now(),
  updated_at      timestamp without time zone NOT NULL DEFAULT now(),
  unique_id       text NOT NULL UNIQUE,
  org_name        text,
  legal_name      text NOT NULL,
  jurisdiction    text,
  registration_id text,
  attrs           jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_organization_created_at ON public.organization (created_at);
CREATE INDEX IF NOT EXISTS idx_organization_updated_at ON public.organization (updated_at);
CREATE INDEX IF NOT EXISTS idx_organization_org_name ON public.organization (org_name);
CREATE INDEX IF NOT EXISTS idx_organization_legal_name ON public.organization (legal_name);
CREATE INDEX IF NOT EXISTS idx_organization_jurisdiction ON public.organization (jurisdiction);
CREATE INDEX IF NOT EXISTS idx_organization_registration_id ON public.organization (registration_id);

-- Upsert a Organization AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id text;
    v_row       bigint;
BEGIN
    v_unique_id := (_rec->>'unique_id');

    -- 1) Upsert into organization.
    v_row := public.organization_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'organization'::citext,
        _natural_key := v_unique_id::citext,
        _table_name  := 'public.organization'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_upsert(
    _unique_id       text,
    _org_name        text DEFAULT NULL,
    _legal_name      text,
    _jurisdiction    text DEFAULT NULL,
    _registration_id text DEFAULT NULL,
    _attrs           jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _legal_name IS NULL THEN
        RAISE EXCEPTION 'organization_upsert requires non-NULL unique_id and legal_name';
    END IF;

    INSERT INTO public.organization (
        unique_id, org_name, legal_name, jurisdiction, registration_id, attrs
    ) VALUES (
        _unique_id, _org_name, _legal_name, _jurisdiction, _registration_id, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        org_name        = COALESCE(EXCLUDED.org_name,        organization.org_name),
        legal_name      = COALESCE(EXCLUDED.legal_name,      organization.legal_name),
        jurisdiction    = COALESCE(EXCLUDED.jurisdiction,    organization.jurisdiction),
        registration_id = COALESCE(EXCLUDED.registration_id, organization.registration_id),
        attrs           = organization.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at      = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id       text;
    v_legal_name      text;
    v_org_name        text;
    v_active          boolean;
    v_jurisdiction    text;
    v_founding_date   timestamp without time zone;
    v_registration_id text;
    v_industry        text;
    v_markets         text[];
    v_non_profit      boolean;
    v_headcount       integer;
    v_attrs           jsonb;
BEGIN
    v_unique_id       := NULLIF(_rec->>'unique_id', '');
    v_legal_name      := NULLIF(_rec->>'legal_name', '');
    v_org_name        := NULLIF(_rec->>'org_name', '');
    v_jurisdiction    := NULLIF(_rec->>'jurisdiction', '');
    v_registration_id := NULLIF(_rec->>'registration_id', '');
    v_founding_date   := NULLIF(_rec->>'founding_date', '')::timestamp;
    v_industry        := NULLIF(_rec->>'industry', '');
    v_headcount       := NULLIF(_rec->>'headcount', '0')::integer;

    IF _rec ? 'active' THEN
        v_active := (_rec->>'active')::boolean;
    ELSE
        v_active := NULL;
    END IF;

    IF _rec ? 'non_profit' THEN
        v_non_profit := (_rec->>'non_profit')::boolean;
    ELSE
        v_non_profit := NULL;
    END IF;

    -- target markets as JSON array of text, if present
    IF _rec ? 'target_markets' THEN
        SELECT array_agg(elem::text) INTO v_markets
        FROM jsonb_array_elements_text(_rec->'target_markets') AS elem;
    ELSE
        v_markets := NULL;
    END IF;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'founding_date',  v_founding_date,
            'industry',       v_industry,
            'target_markets', v_markets,
            'active',         v_active,
            'non_profit',     v_non_profit,
            'headcount',      v_headcount
        )
    ) || '{}'::jsonb;

    RETURN public.organization_upsert(
        v_unique_id,
        v_org_name,
        v_legal_name,
        v_jurisdiction,
        v_registration_id,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_get_by_id(_row_id bigint)
RETURNS public.organization
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.organization
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_find_by_content(
    _filters jsonb, 
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS SETOF public.organization
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_unique_id       text;
    v_legal_name      text;
    v_org_name        text;
    v_jurisdiction    text;
    v_registration_id text;
    v_count           integer := 0;
    v_params          text[]  := array[]::text[];
    v_sql             text    := 'SELECT * FROM public.organization WHERE TRUE';
BEGIN
    -- 1) Extract filters from JSONB
    v_unique_id       := NULLIF(_filters->>'unique_id', '');
    v_legal_name      := NULLIF(_filters->>'legal_name', '');
    v_org_name        := NULLIF(_filters->>'name', '');
    v_jurisdiction    := NULLIF(_filters->>'jurisdiction', '');
    v_registration_id := NULLIF(_filters->>'registration_id', '');

    -- 2) Build the params array from the filters
    IF v_unique_id IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_unique_id);
        v_sql    := v_sql || format(' AND %I = $%s', 'unique_id', v_count);
    END IF;

    IF v_legal_name IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_legal_name);
        v_sql    := v_sql || format(' AND %I = $%s', 'legal_name', v_count);
    END IF;

    IF v_org_name IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_org_name);
        v_sql    := v_sql || format(' AND %I = $%s', 'org_name', v_count);
    END IF;

    IF v_jurisdiction IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_jurisdiction);
        v_sql    := v_sql || format(' AND %I = $%s', 'jurisdiction', v_count);
    END IF;

    IF v_registration_id IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_registration_id);
        v_sql    := v_sql || format(' AND %I = $%s', 'registration_id', v_count);
    END IF;

    IF v_count = 0 THEN
        RAISE EXCEPTION 'organization_find_by_content requires at least one filter';
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
        WHEN 5 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4], v_params[5];
        WHEN 6 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4], v_params[5], v_params[6];
    END CASE;

    RETURN;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id       bigint,
    id              bigint,
    created_at      timestamp without time zone,
    updated_at      timestamp without time zone,
    unique_id       text,
    org_name        text,
    legal_name      text,
    jurisdiction    text,
    registration_id text,
    attrs           jsonb
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
        a.org_name,
        a.legal_name,
        a.jurisdiction,
        a.registration_id,
        a.attrs
    FROM public.organization a
    JOIN public.entity e ON e.table_name = 'public.organization'::citext AND e.row_id = a.id
    WHERE a.updated_at >= _since
    ORDER BY a.updated_at DESC, a.id ASC
    LIMIT _limit;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.organization_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.organization_find_by_content(jsonb, timestamp without time zone);
DROP FUNCTION IF EXISTS public.organization_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.organization_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.organization_upsert(text, text, text, text, text, jsonb);
DROP FUNCTION IF EXISTS public.organization_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_organization_registration_id;
DROP INDEX IF EXISTS idx_organization_jurisdiction;
DROP INDEX IF EXISTS idx_organization_legal_name;
DROP INDEX IF EXISTS idx_organization_org_name;
DROP INDEX IF EXISTS idx_organization_updated_at;
DROP INDEX IF EXISTS idx_organization_created_at;
DROP TABLE IF EXISTS public.organization;