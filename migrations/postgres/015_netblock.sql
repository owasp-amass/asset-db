-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Netblock Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.netblock (
  id            bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at    timestamp without time zone NOT NULL DEFAULT now(),
  updated_at    timestamp without time zone NOT NULL DEFAULT now(),
  netblock_cidr cidr NOT NULL UNIQUE,
  attrs         jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_netblock_created_at ON public.netblock (created_at);
CREATE INDEX IF NOT EXISTS idx_netblock_updated_at ON public.netblock (updated_at);

-- Upsert a Netblock AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_cidr text;
    v_row  bigint;
BEGIN
    v_cidr := (_rec->>'cidr');

    -- 1) Upsert into netblock.
    v_row := public.netblock_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'netblock'::citext,
        _natural_key := v_cidr::citext,
        _table_name  := 'public.netblock'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by netblock_cidr (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_upsert(
    _netblock_cidr cidr,
    _attrs         jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _netblock_cidr IS NULL THEN
        RAISE EXCEPTION 'netblock_upsert requires non-NULL netblock_cidr';
    END IF;
    IF NOT (_attrs ? 'type') OR (_attrs->>'type') IS NULL THEN
        RAISE EXCEPTION 'netblock_upsert requires non-NULL ip_version';
    END IF;

    INSERT INTO public.netblock (
        netblock_cidr, attrs
    ) VALUES (
        _netblock_cidr, _attrs
    )
    ON CONFLICT (netblock_cidr) DO UPDATE
    SET
        attrs      = netblock.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_cidr    cidr;
    v_version text;
    v_attrs   jsonb;
BEGIN
    v_cidr    := NULLIF(_rec->>'cidr', '')::cidr;
    v_version := NULLIF(_rec->>'type', '');

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'type', v_version,
        )
    ) || '{}'::jsonb;

    RETURN public.netblock_upsert(
        v_cidr,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_get_by_id(_row_id bigint)
RETURNS public.netblock
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, netblock_cidr, attrs
    FROM public.netblock
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.netblock
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, netblock_cidr, attrs
    FROM public.netblock
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.netblock_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.netblock_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.netblock_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.netblock_upsert(cidr, jsonb);
DROP FUNCTION IF EXISTS public.netblock_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_netblock_updated_at;
DROP INDEX IF EXISTS idx_netblock_created_at;
DROP TABLE IF EXISTS public.netblock;