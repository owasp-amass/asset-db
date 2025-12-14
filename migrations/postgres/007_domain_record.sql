-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- DomainRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.domainrecord (
  id              bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at      timestamp without time zone NOT NULL DEFAULT now(),
  updated_at      timestamp without time zone NOT NULL DEFAULT now(),
  domain          citext NOT NULL UNIQUE,
  record_name     text NOT NULL,
  punycode        text,
  extension       text,
  whois_server    citext,
  object_id       text,
  attrs           jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_domainrecord_created_at ON public.domainrecord (created_at);
CREATE INDEX IF NOT EXISTS idx_domainrecord_updated_at ON public.domainrecord (updated_at);
CREATE INDEX IF NOT EXISTS idx_domainrecord_name ON public.domainrecord (record_name);
CREATE INDEX IF NOT EXISTS idx_domainrecord_extension ON public.domainrecord (extension);
CREATE INDEX IF NOT EXISTS idx_domainrecord_punycode ON public.domainrecord (punycode);
CREATE INDEX IF NOT EXISTS idx_domainrecord_whois_server ON public.domainrecord (whois_server);
CREATE INDEX IF NOT EXISTS idx_domainrecord_object_id ON public.domainrecord (object_id);

-- Upsert a DomainRecord AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_domain text;
    v_row    bigint;
BEGIN
    v_domain := (_rec->>'domain');

    -- 1) Upsert into domainrecord.
    v_row := public.domainrecord_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'domainrecord'::citext,
        _natural_key := v_domain::citext,
        _table_name  := 'public.domainrecord'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by domain (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_upsert(
    _domain         text,
    _record_name    text,
    _punycode       text DEFAULT NULL,
    _extension      text DEFAULT NULL,
    _whois_server   citext DEFAULT NULL,
    _object_id      text DEFAULT NULL,
    _attrs          jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _domain IS NULL OR _record_name IS NULL THEN
        RAISE EXCEPTION 'domainrecord_upsert requires non-NULL domain and record_name';
    END IF;

    INSERT INTO public.domainrecord (
        domain, record_name, punycode, extension, whois_server, object_id, attrs
    ) VALUES (
        _domain, _record_name, _punycode, _extension, _whois_server, _object_id, _attrs
    )
    ON CONFLICT (domain) DO UPDATE
    SET
        record_name     = COALESCE(EXCLUDED.record_name,  domainrecord.record_name),
        punycode        = COALESCE(EXCLUDED.punycode,     domainrecord.punycode),
        extension       = COALESCE(EXCLUDED.extension,    domainrecord.extension),
        whois_server    = COALESCE(EXCLUDED.whois_server, domainrecord.whois_server),
        object_id       = COALESCE(EXCLUDED.object_id,    domainrecord.object_id),
        attrs           = domainrecord.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at      = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_domain          text;
    v_record_name     text;
    v_raw_record      text;
    v_record_status   text[];
    v_punycode        text;
    v_extension       text;
    v_created_date    timestamp without time zone;
    v_updated_date    timestamp without time zone;
    v_expiration_date timestamp without time zone;
    v_whois_server    citext;
    v_object_id       text;
    v_dnssec          boolean;
    v_attrs           jsonb;
BEGIN
    v_domain          := NULLIF(_rec->>'domain', '');
    v_record_name     := NULLIF(_rec->>'record_name', '');
    v_raw_record      := NULLIF(_rec->>'raw_record', '');
    v_punycode        := (_rec->>'punycode');
    v_extension       := (_rec->>'extension');
    v_created_date    := NULLIF(_rec->>'created_date', '')::timestamp;
    v_updated_date    := NULLIF(_rec->>'updated_date', '')::timestamp;
    v_expiration_date := NULLIF(_rec->>'expiration_date', '')::timestamp;
    v_whois_server    := (_rec->>'whois_server');
    v_object_id       := (_rec->>'id');
    v_dnssec          := (_rec->>'dnssec')::boolean;

    -- record_status as JSON array of text, if present
    IF _rec ? 'record_status' THEN
        SELECT array_agg(elem::text) INTO v_record_status
        FROM jsonb_array_elements_text(_rec->'record_status') AS elem;
    ELSE
        v_record_status := NULL;
    END IF;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'raw',             v_raw_record,
            'status',          v_record_status,
            'created_date',    v_created_date,
            'updated_date',    v_updated_date,
            'expiration_date', v_expiration_date,
            'dnssec',          v_dnssec
        )
    ) || '{}'::jsonb;

    RETURN public.domainrecord_upsert(
        v_domain,
        v_record_name,
        v_punycode,
        v_extension,
        v_whois_server,
        v_object_id,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_get_by_id(_row_id bigint)
RETURNS public.domainrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.domainrecord
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_find_by_content(
    _filters jsonb, 
    _since   timestamp without time zone DEFAULT NULL
) RETURNS SETOF public.domainrecord
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_domain       text;
    v_record_name  text;
    v_punycode     text;
    v_extension    text;
    v_whois_server citext;
    v_object_id    text;
    v_count        integer := 0;
    v_params       text[]  := array[]::text[];
    v_sql          text    := 'SELECT * FROM public.domainrecord WHERE TRUE';
BEGIN
    -- 1) Extract filters from JSONB
    v_domain       := NULLIF(_filters->>'domain', '');
    v_record_name  := NULLIF(_filters->>'name', '');
    v_punycode     := NULLIF(_filters->>'punycode', '');
    v_extension    := NULLIF(_filters->>'extension', '');
    v_object_id    := NULLIF(_filters->>'id', '');
    v_whois_server := NULLIF(_filters->>'whois_server', '')::citext;

    -- 2) Build the params array from the filters
    IF v_domain IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_domain);
        v_sql    := v_sql || format(' AND %I = $%s', 'domain', v_count);
    END IF;

    IF v_record_name IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_record_name);
        v_sql    := v_sql || format(' AND %I = $%s', 'record_name', v_count);
    END IF;

    IF v_punycode IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_punycode);
        v_sql    := v_sql || format(' AND %I = $%s', 'punycode', v_count);
    END IF;

    IF v_extension IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_extension);
        v_sql    := v_sql || format(' AND %I = $%s', 'extension', v_count);
    END IF;

    IF v_object_id IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_object_id);
        v_sql    := v_sql || format(' AND %I = $%s', 'object_id', v_count);
    END IF;

    IF v_whois_server IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_whois_server::text);
        v_sql    := v_sql || format(' AND %I = $%s', 'whois_server', v_count);
    END IF;

    IF v_count = 0 THEN
        RAISE EXCEPTION 'domainrecord_find_by_content requires at least one filter';
    END IF;

    IF _since IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, _since::text);
        v_sql    := v_sql || format(' AND %I >= $%s', 'updated_at', v_count);
    END IF;

    -- 3) Add the ORDER BY clause
    v_sql := v_sql || ' ORDER BY updated_at ASC, id ASC';

    -- 4) Execute dynamic SQL and return results
    RETURN QUERY EXECUTE v_sql USING ALL v_params;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_updated_since(_since timestamp without time zone) 
RETURNS SETOF public.domainrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.domainrecord
    WHERE updated_at >= _since
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.domainrecord_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.domainrecord_find_by_content(jsonb, timestamp without time zone);
DROP FUNCTION IF EXISTS public.domainrecord_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.domainrecord_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.domainrecord_upsert(
    text, text, text, text, citext, text, jsonb
);
DROP FUNCTION IF EXISTS public.domainrecord_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_domainrecord_object_id;
DROP INDEX IF EXISTS idx_domainrecord_whois_server;
DROP INDEX IF EXISTS idx_domainrecord_punycode;
DROP INDEX IF EXISTS idx_domainrecord_extension;
DROP INDEX IF EXISTS idx_domainrecord_name;
DROP INDEX IF EXISTS idx_domainrecord_updated_at;
DROP INDEX IF EXISTS idx_domainrecord_created_at;
DROP TABLE IF EXISTS public.domainrecord;