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
  id_value   text NOT NULL,
  id_type    text NOT NULL,
  attrs      jsonb NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE(id_value, id_type)
);
CREATE INDEX IF NOT EXISTS idx_identifier_created_at ON public.identifier (created_at);
CREATE INDEX IF NOT EXISTS idx_identifier_updated_at ON public.identifier (updated_at);
CREATE INDEX IF NOT EXISTS idx_identifier_id_value ON public.identifier (id_value);
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
    v_unique_id := NULLIF(_rec->>'unique_id', '');

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
    _id_value  text,
    _id_type   text DEFAULT NULL,
    _attrs     jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _id_value IS NULL OR _id_type IS NULL THEN
        RAISE EXCEPTION 'identifier_upsert requires non-NULL unique_id, id_value, and id_type';
    END IF;

    INSERT INTO public.identifier (
        unique_id, id_value, id_type, attrs
    ) VALUES (
        _unique_id, _id_value, _id_type, _attrs
    )
    ON CONFLICT (id_value, id_type) DO UPDATE
    SET
        unique_id  = EXCLUDED.unique_id,
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
    v_id_value        text;
    v_id_type         text;
    v_status          text;
    v_created_date    timestamp;
    v_updated_date    timestamp;
    v_expiration_date timestamp;
    v_attrs           jsonb;
BEGIN
    v_unique_id       := NULLIF(_rec->>'unique_id', '');
    v_id_value        := NULLIF(_rec->>'id', '');
    v_id_type         := NULLIF(_rec->>'id_type', '');
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
        v_id_value,
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
    SELECT *
    FROM public.identifier
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: unique_id, id, id_type
-- Requires at least one supported filter to be present.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS TABLE (
    entity_id  bigint,
    id         bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    unique_id  text,
    id_value   text,
    id_type    text,
    attrs      jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    WITH f AS (
        SELECT
            NULLIF(_filters->>'unique_id','') AS unique_id,
            NULLIF(_filters->>'id','')        AS id_value,
            NULLIF(_filters->>'id_type','')   AS id_type,
            _since                            AS since_ts,
            GREATEST(COALESCE(_limit, 0), 0)  AS lim
    )
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.unique_id,
        a.id_value,
        a.id_type,
        a.attrs
    FROM public.identifier a
    JOIN public.entity e ON e.table_name = 'public.identifier'::citext AND e.row_id = a.id
    CROSS JOIN f
    WHERE
        -- require at least one supported filter
        (f.unique_id IS NOT NULL OR f.id_value IS NOT NULL OR f.id_type IS NOT NULL)
      AND (f.unique_id IS NULL OR a.unique_id = f.unique_id)
      AND (f.id_value  IS NULL OR a.id_value  = f.id_value)
      AND (f.id_type   IS NULL OR a.id_type   = f.id_type)
      AND (f.since_ts  IS NULL OR a.updated_at >= f.since_ts)
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT CASE WHEN (SELECT lim FROM f) > 0 THEN (SELECT lim FROM f) ELSE ALL END;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT 0
) RETURNS TABLE (
    entity_id  bigint,
    id         bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    unique_id  text,
    id_value   text,
    id_type    text,
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
        a.unique_id,
        a.id_value,
        a.id_type,
        a.attrs
    FROM public.identifier a
    JOIN public.entity e ON e.table_name = 'public.identifier'::citext AND e.row_id = a.id
    CROSS JOIN p
    WHERE a.updated_at >= _since
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT CASE WHEN (SELECT lim FROM p) > 0 THEN (SELECT lim FROM p) ELSE ALL END;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.identifier_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.identifier_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.identifier_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.identifier_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.identifier_upsert(text, text, text, jsonb);
DROP FUNCTION IF EXISTS public.identifier_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_identifier_id_type;
DROP INDEX IF EXISTS idx_identifier_id_value;
DROP INDEX IF EXISTS idx_identifier_updated_at;
DROP INDEX IF EXISTS idx_identifier_created_at;
DROP TABLE IF EXISTS public.identifier;