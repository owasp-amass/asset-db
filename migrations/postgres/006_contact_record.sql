-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- ContactRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.contactrecord (
  id            bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at    timestamp without time zone NOT NULL DEFAULT now(),
  updated_at    timestamp without time zone NOT NULL DEFAULT now(),
  discovered_at text NOT NULL UNIQUE,
  attrs         jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_contactrecord_created_at ON public.contactrecord (created_at);
CREATE INDEX IF NOT EXISTS idx_contactrecord_updated_at ON public.contactrecord (updated_at);

-- Upsert a ContactRecord AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_discovered_at text;
    v_row           bigint;
BEGIN
    v_discovered_at := (_rec->>'discovered_at');

    -- 1) Upsert into contactrecord.
    v_row := public.contactrecord_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'contactrecord'::citext,
        _natural_key := v_discovered_at::citext,
        _table_name  := 'public.contactrecord'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by discovered_at (scalar param). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_upsert(
    _discovered_at text,
    _attrs         jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _discovered_at IS NULL THEN
        RAISE EXCEPTION 'contactrecord_upsert requires non-NULL discovered_at';
    END IF;

    INSERT INTO public.contactrecord (
        discovered_at
    ) VALUES (
        _discovered_at
    )
    ON CONFLICT (discovered_at) DO UPDATE
    SET
        attrs      = contactrecord.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts key: discovered_at. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_discovered_at text;
BEGIN
    v_discovered_at := NULLIF(_rec->>'discovered_at', '');

    RETURN public.contactrecord_upsert(v_discovered_at);
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_get_by_id(_row_id bigint)
RETURNS public.contactrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, discovered_at, attrs
    FROM public.contactrecord
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.contactrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, discovered_at, attrs
    FROM public.contactrecord
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.contactrecord_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.contactrecord_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.contactrecord_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.contactrecord_upsert(text, jsonb);
DROP FUNCTION IF EXISTS public.contactrecord_upsert_entity_json(jsonb)

DROP INDEX IF EXISTS idx_contactrecord_updated_at;
DROP INDEX IF EXISTS idx_contactrecord_created_at;
DROP TABLE IF EXISTS public.contactrecord;