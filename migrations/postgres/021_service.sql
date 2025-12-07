-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Service Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.service (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  unique_id text NOT NULL UNIQUE,
  service_type text NOT NULL,
  output_data text,
  output_length integer,
  attributes jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_service_created_at
  ON public.service(created_at);
CREATE INDEX IF NOT EXISTS idx_service_updated_at
  ON public.service(updated_at);
CREATE INDEX IF NOT EXISTS idx_service_service_type
  ON public.service(service_type);
CREATE INDEX IF NOT EXISTS idx_service_output_length
  ON public.service(output_length);

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_upsert(
    _unique_id      text,
    _service_type   text,
    _output_data    text    DEFAULT NULL,
    _output_length  integer DEFAULT NULL,
    _attributes     jsonb   DEFAULT '{}'::jsonb
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
        unique_id,
        service_type,
        output_data,
        output_length,
        attributes
    ) VALUES (
        _unique_id,
        _service_type,
        _output_data,
        _output_length,
        COALESCE(_attributes, '{}'::jsonb)
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        service_type  = COALESCE(EXCLUDED.service_type,  service.service_type),
        output_data   = COALESCE(EXCLUDED.output_data,   service.output_data),
        output_length = COALESCE(EXCLUDED.output_length, service.output_length),
        attributes    = CASE
                          WHEN EXCLUDED.attributes IS NULL
                            THEN service.attributes
                          ELSE service.attributes || EXCLUDED.attributes
                        END,
        updated_at    = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Accepts keys:
--   unique_id, service_type, output_data, output_length, attributes
-- Returns row id.
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
    v_attributes    jsonb;
BEGIN
    v_unique_id    := _rec->>'unique_id';
    v_service_type := _rec->>'service_type';
    v_output_data  := NULLIF(_rec->>'output_data', '');

    IF _rec ? 'output_length' THEN
        v_output_length := NULLIF(_rec->>'output_length', '')::integer;
    ELSE
        v_output_length := NULL;
    END IF;

    IF _rec ? 'attributes' THEN
        v_attributes := COALESCE(_rec->'attributes', '{}'::jsonb);
    ELSE
        v_attributes := '{}'::jsonb;
    END IF;

    RETURN public.service_upsert(
        v_unique_id,
        v_service_type,
        v_output_data,
        v_output_length,
        v_attributes
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by unique_id (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_get_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.service
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_get_by_unique_id(
    _unique_id text
) RETURNS public.service
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.service
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by service_type (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_find_by_type(
    _service_type text
) RETURNS SETOF public.service
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.service
    WHERE (CASE
             WHEN strpos(_service_type, '%') > 0 OR strpos(_service_type, '_') > 0
               THEN service_type ILIKE _service_type
             ELSE service_type = _service_type
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.service
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.service
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a Service AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_upsert_entity(
    _unique_id      text,
    _service_type   text,
    _output_data    text    DEFAULT NULL,
    _output_length  integer DEFAULT NULL,
    _attributes     jsonb   DEFAULT '{}'::jsonb,   -- service-level attributes
    _extra_attrs    jsonb   DEFAULT '{}'::jsonb,   -- additional entity attrs
    _etype_name     citext  DEFAULT 'service'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.service%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
    v_attr_merged jsonb;
BEGIN
    IF _unique_id IS NULL OR _service_type IS NULL THEN
        RAISE EXCEPTION 'service_upsert_entity requires non-NULL unique_id and service_type';
    END IF;

    -- 1) Upsert into service by unique_id, merging attributes.
    INSERT INTO public.service (
        unique_id,
        service_type,
        output_data,
        output_length,
        attributes
    ) VALUES (
        _unique_id,
        _service_type,
        _output_data,
        _output_length,
        COALESCE(_attributes, '{}'::jsonb)
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        service_type  = COALESCE(EXCLUDED.service_type,  service.service_type),
        output_data   = COALESCE(EXCLUDED.output_data,   service.output_data),
        output_length = COALESCE(EXCLUDED.output_length, service.output_length),
        attributes    = CASE
                          WHEN EXCLUDED.attributes IS NULL
                            THEN service.attributes
                          ELSE service.attributes || EXCLUDED.attributes
                        END,
        updated_at    = now()
    RETURNING * INTO v_row;

    -- 2) Merge stored attributes with caller-supplied extra attrs for the entity.
    v_attr_merged := v_row.attributes || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Build attrs from the core service fields plus merged attributes.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'unique_id',      v_row.unique_id,
            'service_type',   v_row.service_type,
            'output_data',    v_row.output_data,
            'output_length',  v_row.output_length,
            'attributes',     v_attr_merged
        )
    );

    -- 4) Upsert into entity via the generic helper (entity_upsert),
    -- using unique_id as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                    -- e.g. 'service'
        _natural_key := v_row.unique_id::citext,        -- canonical key
        _table_name  := 'service'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map unique_id -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_get_entity_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.service s
    JOIN public.entity e
      ON e.table_name = 'service'
     AND e.row_id     = s.id
    WHERE s.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+Service by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_get_with_entity_by_unique_id(
    _unique_id text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    service_row  public.service
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        s
    FROM public.service s
    JOIN public.entity e
      ON e.table_name = 'service'
     AND e.row_id     = s.id
    WHERE s.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.service_upsert(text, text, text, integer, jsonb);
DROP FUNCTION IF EXISTS public.service_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.service_get_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.service_get_by_unique_id(text);
DROP FUNCTION IF EXISTS public.service_find_by_type(text);
DROP FUNCTION IF EXISTS public.service_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.service_upsert_entity(
    text, text, text, integer, jsonb, jsonb, citext);
DROP FUNCTION IF EXISTS public.service_get_entity_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.service_get_with_entity_by_unique_id(text);

DROP INDEX IF EXISTS idx_service_output_length;
DROP INDEX IF EXISTS idx_service_service_type;
DROP INDEX IF EXISTS idx_service_updated_at;
DROP INDEX IF EXISTS idx_service_created_at;
DROP TABLE IF EXISTS public.service;