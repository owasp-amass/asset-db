-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- File Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.file (
  id         bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  file_url   text NOT NULL UNIQUE,
  basename   text,
  file_type  text,
  attrs      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_file_created_at ON public.file (created_at);
CREATE INDEX IF NOT EXISTS idx_file_updated_at ON public.file (updated_at);
CREATE INDEX IF NOT EXISTS idx_file_basename ON public.file (basename);
CREATE INDEX IF NOT EXISTS idx_file_file_type ON public.file (file_type);

-- Upsert a File AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_url text;
    v_row bigint;
BEGIN
    v_url := NULLIF(_rec->>'url', '');

    -- 1) Upsert into file.
    v_row := public.file_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'file'::citext,
        _natural_key := v_url::citext,
        _table_name  := 'public.file'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by file_url (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_upsert(
    _file_url  text,
    _basename  text DEFAULT NULL,
    _file_type text DEFAULT NULL,
    _attrs     jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _file_url IS NULL THEN
        RAISE EXCEPTION 'file_upsert requires non-NULL file_url';
    END IF;

    INSERT INTO public.file (
        file_url, basename, file_type, attrs
    ) VALUES (
        _file_url, _basename, _file_type, _attrs
    )
    ON CONFLICT (file_url) DO UPDATE
    SET
        basename   = COALESCE(EXCLUDED.basename,  file.basename),
        file_type  = COALESCE(EXCLUDED.file_type, file.file_type),
        attrs      = file.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_file_url  text;
    v_basename  text;
    v_file_type text;
BEGIN
    v_file_url  := NULLIF(_rec->>'url', '');
    v_basename  := (_rec->>'name');
    v_file_type := (_rec->>'type');

    RETURN public.file_upsert(
        v_file_url,
        v_basename,
        v_file_type
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_get_by_id(_row_id bigint)
RETURNS public.file
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.file
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: url (file_url), name (basename), type (file_type)
-- Requires at least one supported filter to be present.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS TABLE (
    entity_id  bigint,
    id         bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    file_url   text,
    basename   text,
    file_type  text,
    attrs      jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    WITH f AS (
        SELECT
            NULLIF(_filters->>'url',  '')    AS file_url,
            NULLIF(_filters->>'name', '')    AS basename,
            NULLIF(_filters->>'type', '')    AS file_type,
            _since                           AS since_ts,
            GREATEST(COALESCE(_limit, 0), 0) AS lim
    )
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.file_url,
        a.basename,
        a.file_type,
        a.attrs
    FROM public.file a
    JOIN public.entity e ON e.table_name = 'public.file'::citext AND e.row_id = a.id
    CROSS JOIN f
    WHERE
        -- require at least one supported filter
        (f.file_url IS NOT NULL OR f.basename IS NOT NULL OR f.file_type IS NOT NULL)
      AND (f.file_url  IS NULL OR a.file_url  = f.file_url)
      AND (f.basename  IS NULL OR a.basename  = f.basename)
      AND (f.file_type IS NULL OR a.file_type = f.file_type)
      AND (f.since_ts  IS NULL OR a.updated_at >= f.since_ts)
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT CASE WHEN (SELECT lim FROM f) > 0 THEN (SELECT lim FROM f) ELSE ALL END;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT 0
) RETURNS TABLE (
    entity_id  bigint,
    id         bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    file_url   text,
    basename   text,
    file_type  text,
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
        a.file_url,
        a.basename,
        a.file_type,
        a.attrs
    FROM public.file a
    JOIN public.entity e ON e.table_name = 'public.file'::citext AND e.row_id = a.id
    CROSS JOIN p
    WHERE a.updated_at >= _since
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT CASE WHEN (SELECT lim FROM p) > 0 THEN (SELECT lim FROM p) ELSE ALL END;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.file_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.file_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.file_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.file_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.file_upsert(text, text, text, jsonb);
DROP FUNCTION IF EXISTS public.file_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_file_file_type;
DROP INDEX IF EXISTS idx_file_basename;
DROP INDEX IF EXISTS idx_file_updated_at;
DROP INDEX IF EXISTS idx_file_created_at;
DROP TABLE IF EXISTS public.file;