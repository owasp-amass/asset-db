-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- IPNetRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.ipnetrecord (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  record_cidr cidr NOT NULL UNIQUE,
  record_name text NOT NULL,
  ip_version text NOT NULL,
  handle text NOT NULL UNIQUE,
  method text,
  record_status text[],
  created_date timestamp without time zone,
  updated_date timestamp without time zone,
  whois_server citext,
  parent_handle text,
  start_address inet,
  end_address inet,
  country text
);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_created_at
  ON public.ipnetrecord(created_at);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_updated_at
  ON public.ipnetrecord(updated_at);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_name
  ON public.ipnetrecord(record_name);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_type
  ON public.ipnetrecord(ip_version);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_start_address
  ON public.ipnetrecord(start_address);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_end_address
  ON public.ipnetrecord(end_address);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_whois_server
  ON public.ipnetrecord(whois_server);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_method
  ON public.ipnetrecord(method);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_country
  ON public.ipnetrecord(country);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_parent_handle
  ON public.ipnetrecord(parent_handle);

-- Upsert by record_cidr / handle, with merge semantics similar to autnumrecord_upsert.
-- Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_upsert(
    _record_cidr   cidr,
    _record_name   text,
    _ip_version    text,
    _handle        text,
    _method        text DEFAULT NULL,
    _record_status text[] DEFAULT NULL,
    _created_date  timestamp without time zone DEFAULT NULL,
    _updated_date  timestamp without time zone DEFAULT NULL,
    _whois_server  citext DEFAULT NULL,
    _parent_handle text DEFAULT NULL,
    _start_address inet DEFAULT NULL,
    _end_address   inet DEFAULT NULL,
    _country       text DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id_cidr   bigint;
    v_id_handle bigint;
    v_id        bigint;
BEGIN
    IF _record_cidr IS NULL OR _record_name IS NULL
       OR _ip_version IS NULL OR _handle IS NULL THEN
        RAISE EXCEPTION
          'ipnetrecord_upsert requires non-NULL record_cidr, record_name, ip_version, handle';
    END IF;

    -- Lock rows if present to avoid races while merging.
    SELECT id INTO v_id_cidr
    FROM public.ipnetrecord
    WHERE record_cidr = _record_cidr
    FOR UPDATE SKIP LOCKED;

    SELECT id INTO v_id_handle
    FROM public.ipnetrecord
    WHERE handle = _handle
    FOR UPDATE SKIP LOCKED;

    IF v_id_cidr IS NOT NULL AND v_id_handle IS NOT NULL AND v_id_cidr <> v_id_handle THEN
        -- Merge: keep the handle-owned row; drop the other after updating it with incoming fields.
        UPDATE public.ipnetrecord
        SET
            record_cidr   = _record_cidr,
            record_name   = COALESCE(_record_name,   record_name),
            ip_version    = COALESCE(_ip_version,    ip_version),
            method        = COALESCE(_method,        method),
            record_status = COALESCE(_record_status, record_status),
            created_date  = COALESCE(_created_date,  created_date),
            updated_date  = COALESCE(_updated_date,  updated_date),
            whois_server  = COALESCE(_whois_server,  whois_server),
            parent_handle = COALESCE(_parent_handle, parent_handle),
            start_address = COALESCE(_start_address, start_address),
            end_address   = COALESCE(_end_address,   end_address),
            country       = COALESCE(_country,       country),
            updated_at    = now()
        WHERE id = v_id_handle;

        DELETE FROM public.ipnetrecord WHERE id = v_id_cidr;

        v_id := v_id_handle;

    ELSIF v_id_cidr IS NOT NULL OR v_id_handle IS NOT NULL THEN
        -- Update whichever existing row we found.
        v_id := COALESCE(v_id_cidr, v_id_handle);

        UPDATE public.ipnetrecord
        SET
            record_cidr   = _record_cidr,
            record_name   = COALESCE(_record_name,   record_name),
            ip_version    = COALESCE(_ip_version,    ip_version),
            handle        = _handle,
            method        = COALESCE(_method,        method),
            record_status = COALESCE(_record_status, record_status),
            created_date  = COALESCE(_created_date,  created_date),
            updated_date  = COALESCE(_updated_date,  updated_date),
            whois_server  = COALESCE(_whois_server,  whois_server),
            parent_handle = COALESCE(_parent_handle, parent_handle),
            start_address = COALESCE(_start_address, start_address),
            end_address   = COALESCE(_end_address,   end_address),
            country       = COALESCE(_country,       country),
            updated_at    = now()
        WHERE id = v_id;

    ELSE
        -- Insert new row.
        INSERT INTO public.ipnetrecord (
            record_cidr,
            record_name,
            ip_version,
            handle,
            method,
            record_status,
            created_date,
            updated_date,
            whois_server,
            parent_handle,
            start_address,
            end_address,
            country
        ) VALUES (
            _record_cidr,
            _record_name,
            _ip_version,
            _handle,
            _method,
            _record_status,
            _created_date,
            _updated_date,
            _whois_server,
            _parent_handle,
            _start_address,
            _end_address,
            _country
        )
        RETURNING id INTO v_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Accepts keys:
--   record_cidr, record_name, ip_version, handle, method, record_status (array),
--   created_date, updated_date, whois_server, parent_handle, start_address,
--   end_address, country
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_record_cidr   cidr;
    v_record_name   text;
    v_ip_version    text;
    v_handle        text;
    v_method        text;
    v_record_status text[];
    v_created_date  timestamp without time zone;
    v_updated_date  timestamp without time zone;
    v_whois_server  citext;
    v_parent_handle text;
    v_start_address inet;
    v_end_address   inet;
    v_country       text;
BEGIN
    v_record_cidr := NULLIF(_rec->>'record_cidr', '')::cidr;
    v_record_name := _rec->>'record_name';
    v_ip_version  := _rec->>'ip_version';
    v_handle      := _rec->>'handle';
    v_method      := NULLIF(_rec->>'method', '');
    v_created_date := NULLIF(_rec->>'created_date', '')::timestamp;
    v_updated_date := NULLIF(_rec->>'updated_date', '')::timestamp;
    v_whois_server := NULLIF(_rec->>'whois_server', '');
    v_parent_handle := NULLIF(_rec->>'parent_handle', '');
    v_start_address := NULLIF(_rec->>'start_address', '')::inet;
    v_end_address   := NULLIF(_rec->>'end_address', '')::inet;
    v_country       := NULLIF(_rec->>'country', '');

    IF _rec ? 'record_status' THEN
        SELECT array_agg(elem::text)
        INTO v_record_status
        FROM jsonb_array_elements_text(_rec->'record_status') AS elem;
    ELSE
        v_record_status := NULL;
    END IF;

    RETURN public.ipnetrecord_upsert(
        v_record_cidr,
        v_record_name,
        v_ip_version,
        v_handle,
        v_method,
        v_record_status,
        v_created_date,
        v_updated_date,
        v_whois_server,
        v_parent_handle,
        v_start_address,
        v_end_address,
        v_country
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by record_cidr (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_get_id_by_record_cidr(
    _record_cidr cidr
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.ipnetrecord
    WHERE record_cidr = _record_cidr
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get the id by handle (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_get_id_by_handle(
    _handle text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.ipnetrecord
    WHERE handle = _handle
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by record_cidr
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_get_by_record_cidr(
    _record_cidr cidr
) RETURNS public.ipnetrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.ipnetrecord
    WHERE record_cidr = _record_cidr
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by handle
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_get_by_handle(
    _handle text
) RETURNS public.ipnetrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.ipnetrecord
    WHERE handle = _handle
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by whois server (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_find_by_whois(
    _whois citext
) RETURNS SETOF public.ipnetrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.ipnetrecord
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
CREATE OR REPLACE FUNCTION public.ipnetrecord_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.ipnetrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.ipnetrecord
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert an IPNetRecord AND its corresponding Entity.
-- Uses record_cidr as the canonical natural key.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_upsert_entity(
    _record_cidr   cidr,
    _record_name   text,
    _ip_version    text,
    _handle        text,
    _method        text DEFAULT NULL,
    _record_status text[] DEFAULT NULL,
    _created_date  timestamp without time zone DEFAULT NULL,
    _updated_date  timestamp without time zone DEFAULT NULL,
    _whois_server  citext DEFAULT NULL,
    _parent_handle text DEFAULT NULL,
    _start_address inet DEFAULT NULL,
    _end_address   inet DEFAULT NULL,
    _country       text DEFAULT NULL,
    _extra_attrs   jsonb  DEFAULT '{}'::jsonb,          -- for caller-provided extra attributes
    _etype_name    citext DEFAULT 'ipnetrecord'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.ipnetrecord%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _record_cidr IS NULL OR _record_name IS NULL
       OR _ip_version IS NULL OR _handle IS NULL THEN
        RAISE EXCEPTION
          'ipnetrecord_upsert_entity requires non-NULL record_cidr, record_name, ip_version, handle';
    END IF;

    -- 1) Upsert into ipnetrecord by record_cidr (canonical key for this entity type).
    INSERT INTO public.ipnetrecord (
        record_cidr,
        record_name,
        ip_version,
        handle,
        method,
        record_status,
        created_date,
        updated_date,
        whois_server,
        parent_handle,
        start_address,
        end_address,
        country
    ) VALUES (
        _record_cidr,
        _record_name,
        _ip_version,
        _handle,
        _method,
        _record_status,
        _created_date,
        _updated_date,
        _whois_server,
        _parent_handle,
        _start_address,
        _end_address,
        _country
    )
    ON CONFLICT (record_cidr) DO UPDATE
    SET
        record_name   = COALESCE(EXCLUDED.record_name,   ipnetrecord.record_name),
        ip_version    = COALESCE(EXCLUDED.ip_version,    ipnetrecord.ip_version),
        handle        = COALESCE(EXCLUDED.handle,        ipnetrecord.handle),
        method        = COALESCE(EXCLUDED.method,        ipnetrecord.method),
        record_status = COALESCE(EXCLUDED.record_status, ipnetrecord.record_status),
        created_date  = COALESCE(EXCLUDED.created_date,  ipnetrecord.created_date),
        updated_date  = COALESCE(EXCLUDED.updated_date,  ipnetrecord.updated_date),
        whois_server  = COALESCE(EXCLUDED.whois_server,  ipnetrecord.whois_server),
        parent_handle = COALESCE(EXCLUDED.parent_handle, ipnetrecord.parent_handle),
        start_address = COALESCE(EXCLUDED.start_address, ipnetrecord.start_address),
        end_address   = COALESCE(EXCLUDED.end_address,   ipnetrecord.end_address),
        country       = COALESCE(EXCLUDED.country,       ipnetrecord.country),
        updated_at    = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the ipnetrecord plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'record_cidr',   v_row.record_cidr::text,
            'record_name',   v_row.record_name,
            'ip_version',    v_row.ip_version,
            'handle',        v_row.handle,
            'method',        v_row.method,
            'record_status', v_row.record_status,
            'created_date',  v_row.created_date,
            'updated_date',  v_row.updated_date,
            'whois_server',  v_row.whois_server,
            'parent_handle', v_row.parent_handle,
            'start_address', v_row.start_address::text,
            'end_address',   v_row.end_address::text,
            'country',       v_row.country
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using record_cidr as the natural_key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                       -- e.g. 'ipnetrecord'
        _natural_key := v_row.record_cidr::text::citext,   -- canonical key: CIDR string
        _table_name  := 'ipnetrecord'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map record_cidr -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_get_entity_id_by_record_cidr(
    _record_cidr cidr
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.ipnetrecord r
    JOIN public.entity e
      ON e.table_name = 'ipnetrecord'
     AND e.row_id     = r.id
    WHERE r.record_cidr = _record_cidr
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Map handle -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_get_entity_id_by_handle(
    _handle text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.ipnetrecord r
    JOIN public.entity e
      ON e.table_name = 'ipnetrecord'
     AND e.row_id     = r.id
    WHERE r.handle = _handle
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+IPNetRecord by record_cidr
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_get_with_entity_by_record_cidr(
    _record_cidr cidr
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    ipnet        public.ipnetrecord
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        r
    FROM public.ipnetrecord r
    JOIN public.entity e
      ON e.table_name = 'ipnetrecord'
     AND e.row_id     = r.id
    WHERE r.record_cidr = _record_cidr
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.ipnetrecord_upsert(
    cidr,
    text,
    text,
    text,
    text,
    text[],
    timestamp without time zone,
    timestamp without time zone,
    citext,
    text,
    inet,
    inet,
    text
);
DROP FUNCTION IF EXISTS public.ipnetrecord_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.ipnetrecord_get_id_by_record_cidr(cidr);
DROP FUNCTION IF EXISTS public.ipnetrecord_get_id_by_handle(text);
DROP FUNCTION IF EXISTS public.ipnetrecord_get_by_record_cidr(cidr);
DROP FUNCTION IF EXISTS public.ipnetrecord_get_by_handle(text);
DROP FUNCTION IF EXISTS public.ipnetrecord_find_by_whois(citext);
DROP FUNCTION IF EXISTS public.ipnetrecord_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.ipnetrecord_upsert_entity(
    cidr,
    text,
    text,
    text,
    text,
    text[],
    timestamp without time zone,
    timestamp without time zone,
    citext,
    text,
    inet,
    inet,
    text,
    jsonb,
    citext
);
DROP FUNCTION IF EXISTS public.ipnetrecord_get_entity_id_by_record_cidr(cidr);
DROP FUNCTION IF EXISTS public.ipnetrecord_get_entity_id_by_handle(text);
DROP FUNCTION IF EXISTS public.ipnetrecord_get_with_entity_by_record_cidr(cidr);

DROP INDEX IF EXISTS idx_ipnetrecord_parent_handle;
DROP INDEX IF EXISTS idx_ipnetrecord_country;
DROP INDEX IF EXISTS idx_ipnetrecord_method;
DROP INDEX IF EXISTS idx_ipnetrecord_whois_server;
DROP INDEX IF EXISTS idx_ipnetrecord_end_address;
DROP INDEX IF EXISTS idx_ipnetrecord_start_address;
DROP INDEX IF EXISTS idx_ipnetrecord_type;
DROP INDEX IF EXISTS idx_ipnetrecord_name;
DROP INDEX IF EXISTS idx_ipnetrecord_updated_at;
DROP INDEX IF EXISTS idx_ipnetrecord_created_at;
DROP TABLE IF EXISTS public.ipnetrecord;