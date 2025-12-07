-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- URL Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.url (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  raw_url text NOT NULL UNIQUE,
  host citext NOT NULL,
  url_path text,
  port integer,
  scheme text
);
CREATE INDEX IF NOT EXISTS idx_url_created_at
  ON public.url(created_at);
CREATE INDEX IF NOT EXISTS idx_url_updated_at
  ON public.url(updated_at);
CREATE INDEX IF NOT EXISTS idx_url_host
  ON public.url(host);
CREATE INDEX IF NOT EXISTS idx_url_path
  ON public.url(url_path);
CREATE INDEX IF NOT EXISTS idx_url_port
  ON public.url(port);
CREATE INDEX IF NOT EXISTS idx_url_scheme
  ON public.url(scheme);

-- Upsert by raw_url (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_upsert(
    _raw_url  text,
    _host     citext,
    _url_path text   DEFAULT NULL,
    _port     integer DEFAULT NULL,
    _scheme   text   DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _raw_url IS NULL OR _host IS NULL THEN
        RAISE EXCEPTION 'url_upsert requires non-NULL raw_url and host';
    END IF;

    INSERT INTO public.url (
        raw_url,
        host,
        url_path,
        port,
        scheme
    ) VALUES (
        _raw_url,
        _host,
        _url_path,
        _port,
        _scheme
    )
    ON CONFLICT (raw_url) DO UPDATE
    SET
        host      = COALESCE(EXCLUDED.host,      url.host),
        url_path  = COALESCE(EXCLUDED.url_path,  url.url_path),
        port      = COALESCE(EXCLUDED.port,      url.port),
        scheme    = COALESCE(EXCLUDED.scheme,    url.scheme),
        updated_at= now()
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
    v_raw_url  text;
    v_host     citext;
    v_url_path text;
    v_port     integer;
    v_scheme   text;
BEGIN
    v_raw_url  := _rec->>'raw_url';
    v_host     := (_rec->>'host')::citext;
    v_url_path := NULLIF(_rec->>'url_path', '');
    v_scheme   := NULLIF(_rec->>'scheme', '');

    IF _rec ? 'port' THEN
        v_port := NULLIF(_rec->>'port', '')::integer;
    ELSE
        v_port := NULL;
    END IF;

    RETURN public.url_upsert(
        v_raw_url,
        v_host,
        v_url_path,
        v_port,
        v_scheme
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by raw_url (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_get_id_by_raw_url(
    _raw_url text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.url
    WHERE raw_url = _raw_url
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by raw_url
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_get_by_raw_url(
    _raw_url text
) RETURNS public.url
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.url
    WHERE raw_url = _raw_url
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by host (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_find_by_host(
    _host_pattern text
) RETURNS SETOF public.url
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.url
    WHERE (CASE
             WHEN strpos(_host_pattern, '%') > 0 OR strpos(_host_pattern, '_') > 0
               THEN host ILIKE _host_pattern
             ELSE host = _host_pattern::citext
           END)
    ORDER BY updated_at DESC, id DESC;
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
    SELECT *
    FROM public.url
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a URL AND its corresponding Entity.
-- Uses raw_url as the canonical natural key.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_upsert_entity(
    _raw_url  text,
    _host     citext,
    _url_path text   DEFAULT NULL,
    _port     integer DEFAULT NULL,
    _scheme   text   DEFAULT NULL,
    _extra_attrs jsonb  DEFAULT '{}'::jsonb,          -- caller-provided extra attrs
    _etype_name citext DEFAULT 'url'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.url%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _raw_url IS NULL OR _host IS NULL THEN
        RAISE EXCEPTION 'url_upsert_entity requires non-NULL raw_url and host';
    END IF;

    -- 1) Upsert into url by raw_url.
    INSERT INTO public.url (
        raw_url,
        host,
        url_path,
        port,
        scheme
    ) VALUES (
        _raw_url,
        _host,
        _url_path,
        _port,
        _scheme
    )
    ON CONFLICT (raw_url) DO UPDATE
    SET
        host       = COALESCE(EXCLUDED.host,      url.host),
        url_path   = COALESCE(EXCLUDED.url_path,  url.url_path),
        port       = COALESCE(EXCLUDED.port,      url.port),
        scheme     = COALESCE(EXCLUDED.scheme,    url.scheme),
        updated_at = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the URL plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'raw_url',  v_row.raw_url,
            'host',     v_row.host,
            'url_path', v_row.url_path,
            'port',     v_row.port,
            'scheme',   v_row.scheme
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using raw_url as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                -- e.g. 'url'
        _natural_key := v_row.raw_url::citext,      -- canonical key
        _table_name  := 'url'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map raw_url -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_get_entity_id_by_raw_url(
    _raw_url text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.url u
    JOIN public.entity e
      ON e.table_name = 'url'
     AND e.row_id     = u.id
    WHERE u.raw_url = _raw_url
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+URL by raw_url
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_get_with_entity_by_raw_url(
    _raw_url text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    url_row      public.url
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        u
    FROM public.url u
    JOIN public.entity e
      ON e.table_name = 'url'
     AND e.row_id     = u.id
    WHERE u.raw_url = _raw_url
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.url_upsert(text, citext, text, integer, text);
DROP FUNCTION IF EXISTS public.url_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.url_get_id_by_raw_url(text);
DROP FUNCTION IF EXISTS public.url_get_by_raw_url(text);
DROP FUNCTION IF EXISTS public.url_find_by_host(text);
DROP FUNCTION IF EXISTS public.url_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.url_upsert_entity(
    text, citext, text, integer, text, jsonb, citext);
DROP FUNCTION IF EXISTS public.url_get_entity_id_by_raw_url(text);
DROP FUNCTION IF EXISTS public.url_get_with_entity_by_raw_url(text);

DROP INDEX IF EXISTS idx_url_scheme;
DROP INDEX IF EXISTS idx_url_port;
DROP INDEX IF EXISTS idx_url_path;
DROP INDEX IF EXISTS idx_url_host;
DROP INDEX IF EXISTS idx_url_updated_at;
DROP INDEX IF EXISTS idx_url_created_at;
DROP TABLE IF EXISTS public.url;