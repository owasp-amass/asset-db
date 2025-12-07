-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- DomainRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.domainrecord (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  raw_record text,
  record_name text NOT NULL,
  domain citext NOT NULL UNIQUE,
  record_status text[],
  punycode text,
  extension text,
  created_date timestamp without time zone,
  updated_date timestamp without time zone,
  expiration_date timestamp without time zone,
  whois_server citext,
  object_id text
);
CREATE INDEX IF NOT EXISTS idx_domainrecord_created_at
  ON public.domainrecord(created_at);
CREATE INDEX IF NOT EXISTS idx_domainrecord_updated_at
  ON public.domainrecord(updated_at);
CREATE INDEX IF NOT EXISTS idx_domainrecord_name
  ON public.domainrecord(record_name);
CREATE INDEX IF NOT EXISTS idx_domainrecord_extension
  ON public.domainrecord(extension);
CREATE INDEX IF NOT EXISTS idx_domainrecord_punycode
  ON public.domainrecord(punycode);
CREATE INDEX IF NOT EXISTS idx_domainrecord_whois_server
  ON public.domainrecord(whois_server);
CREATE INDEX IF NOT EXISTS idx_domainrecord_object_id
  ON public.domainrecord(object_id);

-- Upsert by domain (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_upsert(
    _domain         text,
    _record_name    text,
    _raw_record     text DEFAULT NULL,
    _record_status  text[] DEFAULT NULL,
    _punycode       text DEFAULT NULL,
    _extension      text DEFAULT NULL,
    _created_date   timestamp without time zone DEFAULT NULL,
    _updated_date   timestamp without time zone DEFAULT NULL,
    _expiration_date timestamp without time zone DEFAULT NULL,
    _whois_server   citext DEFAULT NULL,
    _object_id      text DEFAULT NULL
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
        domain,
        record_name,
        raw_record,
        record_status,
        punycode,
        extension,
        created_date,
        updated_date,
        expiration_date,
        whois_server,
        object_id
    ) VALUES (
        _domain,
        _record_name,
        _raw_record,
        _record_status,
        _punycode,
        _extension,
        _created_date,
        _updated_date,
        _expiration_date,
        _whois_server,
        _object_id
    )
    ON CONFLICT (domain) DO UPDATE
    SET
        record_name     = COALESCE(EXCLUDED.record_name,     domainrecord.record_name),
        raw_record      = COALESCE(EXCLUDED.raw_record,      domainrecord.raw_record),
        record_status   = COALESCE(EXCLUDED.record_status,   domainrecord.record_status),
        punycode        = COALESCE(EXCLUDED.punycode,        domainrecord.punycode),
        extension       = COALESCE(EXCLUDED.extension,       domainrecord.extension),
        created_date    = COALESCE(EXCLUDED.created_date,    domainrecord.created_date),
        updated_date    = COALESCE(EXCLUDED.updated_date,    domainrecord.updated_date),
        expiration_date = COALESCE(EXCLUDED.expiration_date, domainrecord.expiration_date),
        whois_server    = COALESCE(EXCLUDED.whois_server,    domainrecord.whois_server),
        object_id       = COALESCE(EXCLUDED.object_id,       domainrecord.object_id),
        updated_at      = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd


-- JSONB upsert variant. Accepts keys:
--   domain, record_name, raw_record, record_status (array),
--   punycode, extension, created_date, updated_date, expiration_date,
--   whois_server, object_id
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_domain         text;
    v_record_name    text;
    v_raw_record     text;
    v_record_status  text[];
    v_punycode       text;
    v_extension      text;
    v_created_date   timestamp without time zone;
    v_updated_date   timestamp without time zone;
    v_expiration_date timestamp without time zone;
    v_whois_server   citext;
    v_object_id      text;
BEGIN
    v_domain         := _rec->>'domain';
    v_record_name    := _rec->>'record_name';
    v_raw_record     := NULLIF(_rec->>'raw_record', '');
    v_punycode       := NULLIF(_rec->>'punycode', '');
    v_extension      := NULLIF(_rec->>'extension', '');
    v_created_date   := NULLIF(_rec->>'created_date', '')::timestamp;
    v_updated_date   := NULLIF(_rec->>'updated_date', '')::timestamp;
    v_expiration_date:= NULLIF(_rec->>'expiration_date', '')::timestamp;
    v_whois_server   := NULLIF(_rec->>'whois_server', '');
    v_object_id      := NULLIF(_rec->>'object_id', '');

    -- record_status as JSON array of text, if present
    IF _rec ? 'record_status' THEN
        SELECT array_agg(elem::text)
        INTO v_record_status
        FROM jsonb_array_elements_text(_rec->'record_status') AS elem;
    ELSE
        v_record_status := NULL;
    END IF;

    RETURN public.domainrecord_upsert(
        v_domain,
        v_record_name,
        v_raw_record,
        v_record_status,
        v_punycode,
        v_extension,
        v_created_date,
        v_updated_date,
        v_expiration_date,
        v_whois_server,
        v_object_id
    );
END
$fn$;
-- +migrate StatementEnd


-- Get the id by domain (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_get_id_by_domain(_domain text)
RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.domainrecord
    WHERE domain = _domain
    LIMIT 1;
$fn$;
-- +migrate StatementEnd


-- Return the full row by domain
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_get_by_domain(_domain text)
RETURNS public.domainrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.domainrecord
    WHERE domain = _domain
    LIMIT 1;
$fn$;
-- +migrate StatementEnd


-- Search by whois server (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_find_by_whois(_whois citext)
RETURNS SETOF public.domainrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.domainrecord
    WHERE (CASE
             WHEN strpos(_whois::text, '%') > 0 OR strpos(_whois::text, '_') > 0
               THEN whois_server ILIKE _whois
             ELSE whois_server = _whois
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd


-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.domainrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.domainrecord
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd


-- Upsert a DomainRecord AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_upsert_entity(
    _domain          text,
    _record_name     text,
    _raw_record      text DEFAULT NULL,
    _record_status   text[] DEFAULT NULL,
    _punycode        text DEFAULT NULL,
    _extension       text DEFAULT NULL,
    _created_date    timestamp without time zone DEFAULT NULL,
    _updated_date    timestamp without time zone DEFAULT NULL,
    _expiration_date timestamp without time zone DEFAULT NULL,
    _whois_server    citext DEFAULT NULL,
    _object_id       text DEFAULT NULL,
    _extra_attrs     jsonb  DEFAULT '{}'::jsonb,       -- for caller-provided extra attributes
    _etype_name      citext DEFAULT 'domainrecord'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.domainrecord%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _domain IS NULL OR _record_name IS NULL THEN
        RAISE EXCEPTION 'domainrecord_upsert_entity requires non-NULL domain and record_name';
    END IF;

    -- 1) Upsert into domainrecord by domain.
    INSERT INTO public.domainrecord (
        domain,
        record_name,
        raw_record,
        record_status,
        punycode,
        extension,
        created_date,
        updated_date,
        expiration_date,
        whois_server,
        object_id
    ) VALUES (
        _domain,
        _record_name,
        _raw_record,
        _record_status,
        _punycode,
        _extension,
        _created_date,
        _updated_date,
        _expiration_date,
        _whois_server,
        _object_id
    )
    ON CONFLICT (domain) DO UPDATE
    SET
        record_name     = COALESCE(EXCLUDED.record_name,     domainrecord.record_name),
        raw_record      = COALESCE(EXCLUDED.raw_record,      domainrecord.raw_record),
        record_status   = COALESCE(EXCLUDED.record_status,   domainrecord.record_status),
        punycode        = COALESCE(EXCLUDED.punycode,        domainrecord.punycode),
        extension       = COALESCE(EXCLUDED.extension,       domainrecord.extension),
        created_date    = COALESCE(EXCLUDED.created_date,    domainrecord.created_date),
        updated_date    = COALESCE(EXCLUDED.updated_date,    domainrecord.updated_date),
        expiration_date = COALESCE(EXCLUDED.expiration_date, domainrecord.expiration_date),
        whois_server    = COALESCE(EXCLUDED.whois_server,    domainrecord.whois_server),
        object_id       = COALESCE(EXCLUDED.object_id,       domainrecord.object_id),
        updated_at      = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the domainrecord plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'domain',          v_row.domain,
            'record_name',     v_row.record_name,
            'raw_record',      v_row.raw_record,
            'record_status',   v_row.record_status,
            'punycode',        v_row.punycode,
            'extension',       v_row.extension,
            'created_date',    v_row.created_date,
            'updated_date',    v_row.updated_date,
            'expiration_date', v_row.expiration_date,
            'whois_server',    v_row.whois_server,
            'object_id',       v_row.object_id
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert).
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,               -- e.g. 'domainrecord'
        _natural_key := v_row.domain::citext,      -- canonical key
        _table_name  := 'domainrecord'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd


-- Map domain -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_get_entity_id_by_domain(
    _domain text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.domainrecord d
    JOIN public.entity e
      ON e.table_name = 'domainrecord'
     AND e.row_id     = d.id
    WHERE d.domain = _domain
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd


-- Get Entity+DomainRecord by domain
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_get_with_entity_by_domain(
    _domain text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    domainrec    public.domainrecord
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        d
    FROM public.domainrecord d
    JOIN public.entity e
      ON e.table_name = 'domainrecord'
     AND e.row_id     = d.id
    WHERE d.domain = _domain
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.domainrecord_upsert(
    text,
    text,
    text,
    text[],
    text,
    text,
    timestamp without time zone,
    timestamp without time zone,
    timestamp without time zone,
    citext,
    text
);
DROP FUNCTION IF EXISTS public.domainrecord_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.domainrecord_get_id_by_domain(text);
DROP FUNCTION IF EXISTS public.domainrecord_get_by_domain(text);
DROP FUNCTION IF EXISTS public.domainrecord_find_by_whois(citext);
DROP FUNCTION IF EXISTS public.domainrecord_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.domainrecord_upsert_entity(
    text,
    text,
    text,
    text[],
    text,
    text,
    timestamp without time zone,
    timestamp without time zone,
    timestamp without time zone,
    citext,
    text,
    jsonb,
    citext
);
DROP FUNCTION IF EXISTS public.domainrecord_get_entity_id_by_domain(text);
DROP FUNCTION IF EXISTS public.domainrecord_get_with_entity_by_domain(text);

DROP INDEX IF EXISTS idx_domainrecord_object_id;
DROP INDEX IF EXISTS idx_domainrecord_whois_server;
DROP INDEX IF EXISTS idx_domainrecord_punycode;
DROP INDEX IF EXISTS idx_domainrecord_extension;
DROP INDEX IF EXISTS idx_domainrecord_name;
DROP INDEX IF EXISTS idx_domainrecord_updated_at;
DROP INDEX IF EXISTS idx_domainrecord_created_at;
DROP TABLE IF EXISTS public.domainrecord;