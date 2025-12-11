-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Identifier Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.identifier (
  id         bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  unique_id  text NOT NULL UNIQUE,
  id_type    text,
  attrs      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_identifier_created_at ON public.identifier (created_at);
CREATE INDEX IF NOT EXISTS idx_identifier_updated_at ON public.identifier (updated_at);
CREATE INDEX IF NOT EXISTS idx_identifier_id_type ON public.identifier (id_type);

-- Upsert an Identifier AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       bigint;
    v_unique_id text;
BEGIN
    v_unique_id := (_rec->>'unique_id');

    -- 1) Upsert into identifier by unique_id.
    v_row := public.identifier_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'identifier'::citext,
        _natural_key := v_unique_id::citext,
        _table_name  := 'public.identifier'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_upsert(
    _unique_id text,
    _id_type   text DEFAULT NULL,
    _attrs     jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL THEN
        RAISE EXCEPTION 'identifier_upsert requires non-NULL unique_id';
    END IF;

    INSERT INTO public.identifier (
        unique_id, id_type, attrs
    ) VALUES (
        _unique_id, _id_type, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        id_type    = COALESCE(EXCLUDED.id_type, identifier.id_type),
        attrs      = identifier.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys: unique_id, id_type.
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id       text;
    v_id_type         text;
    v_status          text;
    v_created_date    timestamp;
    v_updated_date    timestamp;
    v_expiration_date timestamp;
    v_attrs           jsonb;
BEGIN
    v_unique_id       := NULLIF(_rec->>'unique_id', '');
    v_id_type         := (_rec->>'id_type');
    v_status          := NULLIF(_rec->>'status', '');
    v_created_date    := NULLIF(_rec->>'created_date', '')::timestamp;
    v_updated_date    := NULLIF(_rec->>'updated_date', '')::timestamp;
    v_expiration_date := NULLIF(_rec->>'expiration_date', '')::timestamp;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'status',          v_status,
            'created_date',    v_created_date,
            'updated_date',    v_updated_date,
            'expiration_date', v_expiration_date
        )
    ) || '{}'::jsonb;

    RETURN public.identifier_upsert(
        v_unique_id,
        v_id_type,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_get_by_id(_row_id bigint)
RETURNS public.identifier
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, unique_id, id_type, attrs
    FROM public.identifier
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.identifier
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, unique_id, id_type, attrs
    FROM public.identifier
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.identifier_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.identifier_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.identifier_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.identifier_upsert(text, text, jsonb);
DROP FUNCTION IF EXISTS public.identifier_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_identifier_id_type;
DROP INDEX IF EXISTS idx_identifier_updated_at;
DROP INDEX IF EXISTS idx_identifier_created_at;
DROP TABLE IF EXISTS public.identifier;