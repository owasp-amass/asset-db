-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- URL Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.url (
  id         bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  raw_url    text NOT NULL UNIQUE,
  scheme     text,
  attrs      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_url_created_at ON public.url (created_at);
CREATE INDEX IF NOT EXISTS idx_url_updated_at ON public.url (updated_at);
CREATE INDEX IF NOT EXISTS idx_url_scheme ON public.url (scheme);

-- Upsert a URL AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_url text;
    v_row bigint;
BEGIN
    v_url := (_rec->>'url');

    -- 1) Upsert into url.
    v_row := public.url_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'url'::citext,
        _natural_key := v_url::citext,
        _table_name  := 'public.url'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by raw_url (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_upsert(
    _raw_url text,
    _scheme  text DEFAULT NULL,
    _attrs   jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _raw_url IS NULL OR _scheme IS NULL OR NOT (_attrs ? 'host') THEN
        RAISE EXCEPTION 'url_upsert requires non-NULL raw_url and scheme and host';
    END IF;

    INSERT INTO public.url (
        raw_url, scheme, attrs
    ) VALUES (
        _raw_url, _scheme, _attrs
    )
    ON CONFLICT (raw_url) DO UPDATE
    SET
        scheme     = COALESCE(EXCLUDED.scheme, url.scheme),
        attrs      = url.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Accepts keys:
--   raw_url, host, url_path, port, scheme
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_url      text;
    v_scheme   text;
    v_username text;
    v_password text;
    v_host     citext;
    v_port     integer;
    v_path     text;
    v_options  text;
    v_fragment text;
    v_attrs    jsonb;
BEGIN
    v_url      := NULLIF(_rec->>'url', '');
    v_scheme   := NULLIF(_rec->>'scheme', '');
    v_username := NULLIF(_rec->>'username', '');
    v_password := NULLIF(_rec->>'password', '');
    v_host     := NULLIF(_rec->>'host', '');
    v_path     := NULLIF(_rec->>'path', '');
    v_options  := NULLIF(_rec->>'options', '');
    v_fragment := NULLIF(_rec->>'fragment', '');

    IF _rec ? 'port' THEN
        v_port := NULLIF(_rec->>'port', '')::integer;
    ELSE
        v_port := NULL;
    END IF;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'username', v_username,
            'password', v_password,
            'host',     v_host,
            'port',     v_port,
            'path',     v_path,
            'options',  v_options,
            'fragment', v_fragment
        )
    ) || '{}'::jsonb;

    RETURN public.url_upsert(
        v_url,
        v_scheme,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_get_by_id(_row_id bigint)
RETURNS public.url
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, raw_url, scheme, attrs
    FROM public.url
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.url
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, raw_url, scheme, attrs
    FROM public.url
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.url_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.url_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.url_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.url_upsert(text, text, jsonb);
DROP FUNCTION IF EXISTS public.url_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_url_scheme;
DROP INDEX IF EXISTS idx_url_updated_at;
DROP INDEX IF EXISTS idx_url_created_at;
DROP TABLE IF EXISTS public.url;