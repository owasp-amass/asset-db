-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- IPAddress Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.ipaddress (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  ip_address inet NOT NULL UNIQUE,
  attrs      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_ipaddress_created_at ON public.ipaddress (created_at);
CREATE INDEX IF NOT EXISTS idx_ipaddress_updated_at ON public.ipaddress (updated_at);

-- Upsert an IPAddress AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row  bigint;
    v_addr text;
BEGIN
    v_addr := (_rec->>'address');

    -- 1) Upsert into ipaddress by ip_address.
    v_row := public.ipaddress_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'ipaddress'::citext,
        _natural_key := v_addr::citext,
        _table_name  := 'public.ipaddress'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by IP address (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_upsert(
    _ip_address inet,
    _attrs      jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _ip_address IS NULL THEN
        RAISE EXCEPTION 'ipaddress_upsert requires non-NULL ip_address';
    END IF;
    IF NOT (_attrs ? 'type') THEN
        RAISE EXCEPTION 'ipaddress_upsert requires attrs to contain key "type"';
    END IF;

    INSERT INTO public.ipaddress (
        ip_address, attrs
    ) VALUES (
        _ip_address, _attrs
    )
    ON CONFLICT (ip_address) DO UPDATE
    SET
        attrs      = ipaddress.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys: ip_address, ip_version.
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_addr  inet;
    v_type  text;
    v_attrs jsonb;
BEGIN
    v_addr := NULLIF(_rec->>'address', '')::inet;
    v_type := NULLIF(_rec->>'type', '');

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'type', v_type,
        )
    ) || '{}'::jsonb;

    RETURN public.ipaddress_upsert(
        v_addr,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_get_by_id(_row_id bigint)
RETURNS public.ipaddress
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, ip_address, attrs
    FROM public.ipaddress
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.ipaddress
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, ip_address, attrs
    FROM public.ipaddress
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.ipaddress_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.ipaddress_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.ipaddress_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.ipaddress_upsert(inet, jsonb);
DROP FUNCTION IF EXISTS public.ipaddress_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_ipaddress_updated_at;
DROP INDEX IF EXISTS idx_ipaddress_created_at;
DROP TABLE IF EXISTS public.ipaddress;