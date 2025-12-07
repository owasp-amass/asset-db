-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Identifier Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.identifier (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  id_type text,
  unique_id text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_identifier_created_at
  ON public.identifier(created_at);
CREATE INDEX IF NOT EXISTS idx_identifier_updated_at
  ON public.identifier(updated_at);
CREATE INDEX IF NOT EXISTS idx_identifier_id_type
  ON public.identifier(id_type);

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_upsert(
    _unique_id text,
    _id_type   text DEFAULT NULL
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
        unique_id,
        id_type
    ) VALUES (
        _unique_id,
        _id_type
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        id_type    = COALESCE(EXCLUDED.id_type, identifier.id_type),
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
    v_unique_id text;
    v_id_type   text;
BEGIN
    v_unique_id := _rec->>'unique_id';
    v_id_type   := NULLIF(_rec->>'id_type', '');

    RETURN public.identifier_upsert(
        v_unique_id,
        v_id_type
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by unique_id (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_get_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.identifier
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_get_by_unique_id(
    _unique_id text
) RETURNS public.identifier
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.identifier
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by id_type (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_find_by_id_type(
    _id_type text
) RETURNS SETOF public.identifier
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.identifier
    WHERE (CASE
             WHEN strpos(_id_type, '%') > 0 OR strpos(_id_type, '_') > 0
               THEN id_type ILIKE _id_type
             ELSE id_type = _id_type
           END)
    ORDER BY updated_at DESC, id DESC;
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
    SELECT *
    FROM public.identifier
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert an Identifier AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_upsert_entity(
    _unique_id   text,
    _id_type     text DEFAULT NULL,
    _extra_attrs jsonb  DEFAULT '{}'::jsonb,        -- for caller-provided extra attributes
    _etype_name  citext DEFAULT 'identifier'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.identifier%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _unique_id IS NULL THEN
        RAISE EXCEPTION 'identifier_upsert_entity requires non-NULL unique_id';
    END IF;

    -- 1) Upsert into identifier by unique_id.
    INSERT INTO public.identifier (
        unique_id,
        id_type
    ) VALUES (
        _unique_id,
        _id_type
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        id_type    = COALESCE(EXCLUDED.id_type, identifier.id_type),
        updated_at = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the identifier plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'unique_id', v_row.unique_id,
            'id_type',   v_row.id_type
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert).
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                 -- e.g. 'identifier'
        _natural_key := v_row.unique_id::citext,     -- canonical key
        _table_name  := 'identifier'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map unique_id -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_get_entity_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.identifier i
    JOIN public.entity e
      ON e.table_name = 'identifier'
     AND e.row_id     = i.id
    WHERE i.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+Identifier by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_get_with_entity_by_unique_id(
    _unique_id text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    identifier_row public.identifier
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        i
    FROM public.identifier i
    JOIN public.entity e
      ON e.table_name = 'identifier'
     AND e.row_id     = i.id
    WHERE i.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.identifier_upsert(text, text);
DROP FUNCTION IF EXISTS public.identifier_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.identifier_get_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.identifier_get_by_unique_id(text);
DROP FUNCTION IF EXISTS public.identifier_find_by_id_type(text);
DROP FUNCTION IF EXISTS public.identifier_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.identifier_upsert_entity(text, text, jsonb, citext);
DROP FUNCTION IF EXISTS public.identifier_get_entity_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.identifier_get_with_entity_by_unique_id(text);

DROP INDEX IF EXISTS idx_identifier_id_type;
DROP INDEX IF EXISTS idx_identifier_updated_at;
DROP INDEX IF EXISTS idx_identifier_created_at;
DROP TABLE IF EXISTS public.identifier;