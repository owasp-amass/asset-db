-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- AutnumRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.autnumrecord (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  record_name text,
  handle text NOT NULL UNIQUE,
  asn integer NOT NULL UNIQUE,
  record_status text,
  created_date timestamp without time zone,
  updated_date timestamp without time zone,
  whois_server citext
);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_created_at ON public.autnumrecord(created_at);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_updated_at ON public.autnumrecord(updated_at);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_name ON public.autnumrecord(record_name);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_whois_server ON public.autnumrecord(whois_server);

-- Upsert by handle/asn (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_upsert(
    _handle         text,
    _asn            integer,
    _record_name    text DEFAULT NULL,
    _record_status  text DEFAULT NULL,
    _created_date   timestamp without time zone DEFAULT NULL,
    _updated_date   timestamp without time zone DEFAULT NULL,
    _whois_server   citext DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id_handle   bigint;
    v_id_asn      bigint;
    v_id          bigint;
BEGIN
    IF _handle IS NULL OR _asn IS NULL THEN
        RAISE EXCEPTION 'autnumrecord_upsert requires non-NULL handle and asn';
    END IF;

    -- Try to find existing rows (lock if present to avoid races during merge)
    SELECT id INTO v_id_handle
    FROM public.autnumrecord
    WHERE handle = _handle
    FOR UPDATE SKIP LOCKED;

    SELECT id INTO v_id_asn
    FROM public.autnumrecord
    WHERE asn = _asn
    FOR UPDATE SKIP LOCKED;

    IF v_id_handle IS NOT NULL AND v_id_asn IS NOT NULL AND v_id_handle <> v_id_asn THEN
        -- Merge: keep the handle-owned row; drop the other after ensuring values land on keeper.
        -- Update the handle row first with all incoming fields (including the ASN).
        UPDATE public.autnumrecord
        SET
            asn           = _asn,
            record_name   = COALESCE(_record_name,   record_name),
            record_status = COALESCE(_record_status, record_status),
            created_date  = COALESCE(_created_date,  created_date),
            updated_date  = COALESCE(_updated_date,  updated_date),
            whois_server  = COALESCE(_whois_server,  whois_server),
            updated_at    = now()
        WHERE id = v_id_handle;

        -- Safe to delete the asn-only row (no declared FK references in the schema you shared).
        DELETE FROM public.autnumrecord WHERE id = v_id_asn;

        v_id := v_id_handle;

    ELSIF v_id_handle IS NOT NULL OR v_id_asn IS NOT NULL THEN
        -- Update the existing row (by whichever matched)
        v_id := COALESCE(v_id_handle, v_id_asn);

        UPDATE public.autnumrecord
        SET
            handle        = _handle, -- keep the canonical handle in sync too
            asn           = _asn,
            record_name   = COALESCE(_record_name,   record_name),
            record_status = COALESCE(_record_status, record_status),
            created_date  = COALESCE(_created_date,  created_date),
            updated_date  = COALESCE(_updated_date,  updated_date),
            whois_server  = COALESCE(_whois_server,  whois_server),
            updated_at    = now()
        WHERE id = v_id;

    ELSE
        -- Insert fresh row
        INSERT INTO public.autnumrecord(
            handle, asn, record_name, record_status,
            created_date, updated_date, whois_server
        ) VALUES (
            _handle, _asn, _record_name, _record_status,
            _created_date, _updated_date, _whois_server
        )
        RETURNING id INTO v_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys: handle, asn, record_name, record_status,
-- created_date, updated_date, whois_server. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_handle        text;
    v_asn           integer;
    v_record_name   text;
    v_record_status text;
    v_created_date  timestamp without time zone;
    v_updated_date  timestamp without time zone;
    v_whois_server  citext;
BEGIN
    v_handle        := (_rec->>'handle');
    v_asn           := NULLIF((_rec->>'asn'), '')::integer;
    v_record_name   := _rec->>'record_name';
    v_record_status := _rec->>'record_status';
    v_created_date  := NULLIF((_rec->>'created_date'), '')::timestamp;
    v_updated_date  := NULLIF((_rec->>'updated_date'), '')::timestamp;
    v_whois_server  := (_rec->>'whois_server');

    RETURN public.autnumrecord_upsert(
        v_handle,
        v_asn,
        v_record_name,
        v_record_status,
        v_created_date,
        v_updated_date,
        v_whois_server
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by handle (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_get_id_by_handle(_handle text)
RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.autnumrecord
    WHERE handle = _handle
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get the id by ASN (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_get_id_by_asn(_asn integer)
RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.autnumrecord
    WHERE asn = _asn
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by handle
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_get_by_handle(_handle text)
RETURNS public.autnumrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.autnumrecord
    WHERE handle = _handle
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by ASN
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_get_by_asn(_asn integer)
RETURNS public.autnumrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.autnumrecord
    WHERE asn = _asn
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by whois server (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_find_by_whois(_whois citext)
RETURNS SETOF public.autnumrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.autnumrecord
    WHERE (CASE
             WHEN strpos(_whois::text, '%') > 0 OR strpos(_whois::text, '_') > 0
               THEN whois_server ILIKE _whois
             ELSE whois_server = _whois
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
CREATE OR REPLACE FUNCTION public.autnumrecord_updated_since(_ts timestamp without time zone)
RETURNS SETOF public.autnumrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.autnumrecord
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert an AutnumRecord AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_upsert_entity(
    _handle         text,
    _asn            integer,
    _record_name    text DEFAULT NULL,
    _record_status  text DEFAULT NULL,
    _created_date   timestamp without time zone DEFAULT NULL,
    _updated_date   timestamp without time zone DEFAULT NULL,
    _whois_server   citext DEFAULT NULL,
    _extra_attrs    jsonb  DEFAULT '{}'::jsonb,  -- for caller-provided extra attributes
    _etype_name     citext DEFAULT 'autnumrecord'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.autnumrecord%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _handle IS NULL OR _asn IS NULL THEN
        RAISE EXCEPTION 'autnumrecord_upsert_entity requires non-NULL handle and asn';
    END IF;

    -- 1) Upsert into autnumrecord by handle.
    INSERT INTO public.autnumrecord (
        handle, asn, record_name, record_status,
        created_date, updated_date, whois_server
    ) VALUES (
        _handle, _asn, _record_name, _record_status,
        _created_date, _updated_date, _whois_server
    )
    ON CONFLICT (handle) DO UPDATE
    SET
        asn           = EXCLUDED.asn,
        record_name   = COALESCE(EXCLUDED.record_name,   autnumrecord.record_name),
        record_status = COALESCE(EXCLUDED.record_status, autnumrecord.record_status),
        created_date  = COALESCE(EXCLUDED.created_date,  autnumrecord.created_date),
        updated_date  = COALESCE(EXCLUDED.updated_date,  autnumrecord.updated_date),
        whois_server  = COALESCE(EXCLUDED.whois_server,  autnumrecord.whois_server),
        updated_at    = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the autnumrecord plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'handle',        v_row.handle,
            'asn',           v_row.asn,
            'record_name',   v_row.record_name,
            'record_status', v_row.record_status,
            'created_date',  v_row.created_date,
            'updated_date',  v_row.updated_date,
            'whois_server',  v_row.whois_server
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,           -- e.g. 'autnumrecord'
        _natural_key := v_row.handle::citext,  -- canonical key for this type
        _table_name  := 'autnumrecord'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_get_entity_id_by_asn(
    _asn integer
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.autnumrecord a
    JOIN public.entity e
      ON e.table_name = 'autnumrecord'
     AND e.row_id     = a.id
    WHERE a.asn = _asn
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_get_entity_id_by_handle(
    _handle text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.autnumrecord a
    JOIN public.entity e
      ON e.table_name = 'autnumrecord'
     AND e.row_id     = a.id
    WHERE a.handle = _handle
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_get_with_entity_by_asn(
    _asn integer
) RETURNS TABLE (
    entity_id   bigint,
    etype_id    smallint,
    natural_key citext,
    entity_attrs jsonb,
    autnum      public.autnumrecord
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        a
    FROM public.autnumrecord a
    JOIN public.entity e
      ON e.table_name = 'autnumrecord'
     AND e.row_id     = a.id
    WHERE a.asn = _asn
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.autnumrecord_upsert(
    text,
    integer,
    text,
    text,
    timestamp without time zone,
    timestamp without time zone,
    citext
);
DROP FUNCTION IF EXISTS public.autnumrecord_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.autnumrecord_get_id_by_handle(text);
DROP FUNCTION IF EXISTS public.autnumrecord_get_id_by_asn(integer);
DROP FUNCTION IF EXISTS public.autnumrecord_get_by_handle(text);
DROP FUNCTION IF EXISTS public.autnumrecord_get_by_asn(integer);
DROP FUNCTION IF EXISTS public.autnumrecord_find_by_whois(citext);
DROP FUNCTION IF EXISTS public.autnumrecord_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.autnumrecord_upsert_entity(
    text,
    integer,
    text,
    text,
    timestamp without time zone,
    timestamp without time zone,
    citext,
    jsonb,
    citext
);
DROP FUNCTION IF EXISTS public.autnumrecord_get_entity_id_by_asn(integer);
DROP FUNCTION IF EXISTS public.autnumrecord_get_entity_id_by_handle(text);
DROP FUNCTION IF EXISTS public.autnumrecord_get_with_entity_by_asn(integer);

DROP INDEX IF EXISTS idx_autnumrecord_whois_server;
DROP INDEX IF EXISTS idx_autnumrecord_name;
DROP INDEX IF EXISTS idx_autnumrecord_updated_at;
DROP INDEX IF EXISTS idx_autnumrecord_created_at;
DROP TABLE IF EXISTS public.autnumrecord;