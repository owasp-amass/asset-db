-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Service Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.service (
  id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at   timestamp without time zone NOT NULL DEFAULT now(),
  updated_at   timestamp without time zone NOT NULL DEFAULT now(),
  unique_id    text NOT NULL UNIQUE,
  service_type text NOT NULL,
  attrs        jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_service_created_at ON public.service (created_at);
CREATE INDEX IF NOT EXISTS idx_service_updated_at ON public.service (updated_at);
CREATE INDEX IF NOT EXISTS idx_service_service_type ON public.service (service_type);

-- Upsert a Service AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id text;
    v_row       bigint;
BEGIN
    v_unique_id := NULLIF(_rec->>'unique_id', '');

    -- 1) Upsert into service.
    v_row := public.service_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'service'::citext,
        _natural_key := v_unique_id::citext,
        _table_name  := 'public.service'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_upsert(
    _unique_id    text,
    _service_type text,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _service_type IS NULL THEN
        RAISE EXCEPTION 'service_upsert requires non-NULL unique_id and service_type';
    END IF;

    INSERT INTO public.service (
        unique_id, service_type, attrs
    ) VALUES (
        _unique_id, _service_type, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        service_type = COALESCE(EXCLUDED.service_type,  service.service_type),
        attrs        = service.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id     text;
    v_service_type  text;
    v_output_data   text;
    v_output_length integer;
    v_attrs         jsonb;
    v_attributes    jsonb;
BEGIN
    v_unique_id    := NULLIF(_rec->>'unique_id', '');
    v_service_type := NULLIF(_rec->>'service_type', '');
    v_output_data  := NULLIF(_rec->>'output', '');

    IF _rec ? 'output_length' THEN
        v_output_length := NULLIF(_rec->>'output_length', '')::integer;
    ELSE
        v_output_length := NULL;
    END IF;

    IF _rec ? 'attributes' THEN
        v_attributes := COALESCE(_rec->'attributes', '{}'::jsonb);
    ELSE
        v_attributes := NULL;
    END IF;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'output',        v_output_data,
            'output_length', v_output_length,
            'attributes',    v_attributes
        )
    ) || '{}'::jsonb;

    RETURN public.service_upsert(
        v_unique_id,
        v_service_type,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_get_by_id(_row_id bigint)
RETURNS public.service
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.service
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: unique_id, service_type
-- Requires at least one supported filter to be present.
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT NULL
) RETURNS TABLE (
    entity_id    bigint,
    id           bigint,
    created_at   timestamp without time zone,
    updated_at   timestamp without time zone,
    unique_id    text,
    service_type text,
    attrs        jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_unique_id    text    := NULLIF(_filters->>'unique_id', '');
    v_service_type text    := NULLIF(_filters->>'service_type', '');
    v_limit        integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    IF v_unique_id IS NULL AND v_service_type IS NULL THEN
        RAISE EXCEPTION 'service_find_by_content requires at least one filter';
    END IF;

    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.unique_id,
            a.service_type,
            a.attrs
        FROM public.service a
        JOIN public.entity e ON e.table_name = 'public.service'::citext AND e.row_id = a.id
        WHERE
            (v_unique_id    IS NULL OR a.unique_id    = v_unique_id)
        AND (v_service_type IS NULL OR a.service_type = v_service_type)
        AND (_since IS NULL OR a.updated_at >= _since)
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.unique_id,
            a.service_type,
            a.attrs
        FROM public.service a
        JOIN public.entity e ON e.table_name = 'public.service'::citext AND e.row_id = a.id
        WHERE
            (v_unique_id    IS NULL OR a.unique_id    = v_unique_id)
        AND (v_service_type IS NULL OR a.service_type = v_service_type)
        AND (_since IS NULL OR a.updated_at >= _since)
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id    bigint,
    id           bigint,
    created_at   timestamp without time zone,
    updated_at   timestamp without time zone,
    unique_id    text,
    service_type text,
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
            a.unique_id,
            a.service_type,
            a.attrs
        FROM public.service a
        JOIN public.entity e ON e.table_name = 'public.service'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.unique_id,
            a.service_type,
            a.attrs
        FROM public.service a
        JOIN public.entity e ON e.table_name = 'public.service'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.service_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.service_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.service_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.service_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.service_upsert(text, text, jsonb);
DROP FUNCTION IF EXISTS public.service_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_service_service_type;
DROP INDEX IF EXISTS idx_service_updated_at;
DROP INDEX IF EXISTS idx_service_created_at;
DROP TABLE IF EXISTS public.service;