-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- File Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.file (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  file_url text NOT NULL UNIQUE,
  basename text,
  file_type text
);
CREATE INDEX IF NOT EXISTS idx_file_created_at
  ON public.file(created_at);
CREATE INDEX IF NOT EXISTS idx_file_updated_at
  ON public.file(updated_at);
CREATE INDEX IF NOT EXISTS idx_file_basename
  ON public.file(basename);
CREATE INDEX IF NOT EXISTS idx_file_file_type
  ON public.file(file_type);

-- Upsert by file_url (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_upsert(
    _file_url  text,
    _basename  text DEFAULT NULL,
    _file_type text DEFAULT NULL
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
        file_url,
        basename,
        file_type
    ) VALUES (
        _file_url,
        _basename,
        _file_type
    )
    ON CONFLICT (file_url) DO UPDATE
    SET
        basename  = COALESCE(EXCLUDED.basename,  file.basename),
        file_type = COALESCE(EXCLUDED.file_type, file.file_type),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys: file_url, basename, file_type.
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
    v_file_url  := _rec->>'file_url';
    v_basename  := NULLIF(_rec->>'basename', '');
    v_file_type := NULLIF(_rec->>'file_type', '');

    RETURN public.file_upsert(
        v_file_url,
        v_basename,
        v_file_type
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by file_url (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_get_id_by_file_url(
    _file_url text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.file
    WHERE file_url = _file_url
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by file_url
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_get_by_file_url(
    _file_url text
) RETURNS public.file
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.file
    WHERE file_url = _file_url
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.file
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.file
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a File AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_upsert_entity(
    _file_url   text,
    _basename   text DEFAULT NULL,
    _file_type  text DEFAULT NULL,
    _extra_attrs jsonb  DEFAULT '{}'::jsonb,        -- for caller-provided extra attributes
    _etype_name  citext DEFAULT 'file'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.file%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _file_url IS NULL THEN
        RAISE EXCEPTION 'file_upsert_entity requires non-NULL file_url';
    END IF;

    -- 1) Upsert into file by file_url.
    INSERT INTO public.file (
        file_url,
        basename,
        file_type
    ) VALUES (
        _file_url,
        _basename,
        _file_type
    )
    ON CONFLICT (file_url) DO UPDATE
    SET
        basename   = COALESCE(EXCLUDED.basename,  file.basename),
        file_type  = COALESCE(EXCLUDED.file_type, file.file_type),
        updated_at = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the file plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'file_url',  v_row.file_url,
            'basename',  v_row.basename,
            'file_type', v_row.file_type
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert).
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                 -- e.g. 'file'
        _natural_key := v_row.file_url::citext,      -- canonical key
        _table_name  := 'file'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map file_url -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_get_entity_id_by_file_url(
    _file_url text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.file f
    JOIN public.entity e
      ON e.table_name = 'file'
     AND e.row_id     = f.id
    WHERE f.file_url = _file_url
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+File by file_url
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_get_with_entity_by_file_url(
    _file_url text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    file_row     public.file
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        f
    FROM public.file f
    JOIN public.entity e
      ON e.table_name = 'file'
     AND e.row_id     = f.id
    WHERE f.file_url = _file_url
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.file_upsert(text, text, text);
DROP FUNCTION IF EXISTS public.file_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.file_get_id_by_file_url(text);
DROP FUNCTION IF EXISTS public.file_get_by_file_url(text);
DROP FUNCTION IF EXISTS public.file_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.file_upsert_entity(text, text, text, jsonb, citext);
DROP FUNCTION IF EXISTS public.file_get_entity_id_by_file_url(text);
DROP FUNCTION IF EXISTS public.file_get_with_entity_by_file_url(text);

DROP INDEX IF EXISTS idx_file_file_type;
DROP INDEX IF EXISTS idx_file_basename;
DROP INDEX IF EXISTS idx_file_updated_at;
DROP INDEX IF EXISTS idx_file_created_at;
DROP TABLE IF EXISTS public.file;