-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- TLSCertificate Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.tlscertificate (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  is_ca boolean,
  tls_version integer,
  key_usage text,
  not_after timestamp without time zone,
  not_before timestamp without time zone,
  ext_key_usage text,
  serial_number text NOT NULL UNIQUE,
  subject_key_id text,
  authority_key_id text,
  issuer_common_name text,
  signature_algorithm text,
  subject_common_name text NOT NULL,
  public_key_algorithm text,
  crl_distribution_points text
);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_created_at
  ON public.tlscertificate(created_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_updated_at
  ON public.tlscertificate(updated_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_tls_version
  ON public.tlscertificate(tls_version);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_common_name
  ON public.tlscertificate(subject_common_name);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_issuer_common_name
  ON public.tlscertificate(issuer_common_name);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_signature_algorithm
  ON public.tlscertificate(signature_algorithm);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_public_key_algorithm
  ON public.tlscertificate(public_key_algorithm);

-- Upsert by serial_number (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert(
    _serial_number          text,
    _subject_common_name    text,
    _is_ca                  boolean DEFAULT NULL,
    _tls_version            integer DEFAULT NULL,
    _key_usage              text DEFAULT NULL,
    _not_after              timestamp without time zone DEFAULT NULL,
    _not_before             timestamp without time zone DEFAULT NULL,
    _ext_key_usage          text DEFAULT NULL,
    _subject_key_id         text DEFAULT NULL,
    _authority_key_id       text DEFAULT NULL,
    _issuer_common_name     text DEFAULT NULL,
    _signature_algorithm    text DEFAULT NULL,
    _public_key_algorithm   text DEFAULT NULL,
    _crl_distribution_points text DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _serial_number IS NULL OR _subject_common_name IS NULL THEN
        RAISE EXCEPTION
          'tlscertificate_upsert requires non-NULL serial_number and subject_common_name';
    END IF;

    INSERT INTO public.tlscertificate (
        is_ca,
        tls_version,
        key_usage,
        not_after,
        not_before,
        ext_key_usage,
        serial_number,
        subject_key_id,
        authority_key_id,
        issuer_common_name,
        signature_algorithm,
        subject_common_name,
        public_key_algorithm,
        crl_distribution_points
    ) VALUES (
        _is_ca,
        _tls_version,
        _key_usage,
        _not_after,
        _not_before,
        _ext_key_usage,
        _serial_number,
        _subject_key_id,
        _authority_key_id,
        _issuer_common_name,
        _signature_algorithm,
        _subject_common_name,
        _public_key_algorithm,
        _crl_distribution_points
    )
    ON CONFLICT (serial_number) DO UPDATE
    SET
        is_ca                  = COALESCE(EXCLUDED.is_ca,                  tlscertificate.is_ca),
        tls_version            = COALESCE(EXCLUDED.tls_version,            tlscertificate.tls_version),
        key_usage              = COALESCE(EXCLUDED.key_usage,              tlscertificate.key_usage),
        not_after              = COALESCE(EXCLUDED.not_after,              tlscertificate.not_after),
        not_before             = COALESCE(EXCLUDED.not_before,             tlscertificate.not_before),
        ext_key_usage          = COALESCE(EXCLUDED.ext_key_usage,          tlscertificate.ext_key_usage),
        subject_key_id         = COALESCE(EXCLUDED.subject_key_id,         tlscertificate.subject_key_id),
        authority_key_id       = COALESCE(EXCLUDED.authority_key_id,       tlscertificate.authority_key_id),
        issuer_common_name     = COALESCE(EXCLUDED.issuer_common_name,     tlscertificate.issuer_common_name),
        signature_algorithm    = COALESCE(EXCLUDED.signature_algorithm,    tlscertificate.signature_algorithm),
        subject_common_name    = COALESCE(EXCLUDED.subject_common_name,    tlscertificate.subject_common_name),
        public_key_algorithm   = COALESCE(EXCLUDED.public_key_algorithm,   tlscertificate.public_key_algorithm),
        crl_distribution_points= COALESCE(EXCLUDED.crl_distribution_points,tlscertificate.crl_distribution_points),
        updated_at             = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Accepts keys:
--   serial_number, subject_common_name, is_ca, tls_version, key_usage,
--   not_after, not_before, ext_key_usage, subject_key_id, authority_key_id,
--   issuer_common_name, signature_algorithm, public_key_algorithm,
--   crl_distribution_points
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_serial_number          text;
    v_subject_common_name    text;
    v_is_ca                  boolean;
    v_tls_version            integer;
    v_key_usage              text;
    v_not_after              timestamp without time zone;
    v_not_before             timestamp without time zone;
    v_ext_key_usage          text;
    v_subject_key_id         text;
    v_authority_key_id       text;
    v_issuer_common_name     text;
    v_signature_algorithm    text;
    v_public_key_algorithm   text;
    v_crl_distribution_points text;
BEGIN
    v_serial_number       := _rec->>'serial_number';
    v_subject_common_name := _rec->>'subject_common_name';
    v_key_usage           := NULLIF(_rec->>'key_usage', '');
    v_ext_key_usage       := NULLIF(_rec->>'ext_key_usage', '');
    v_subject_key_id      := NULLIF(_rec->>'subject_key_id', '');
    v_authority_key_id    := NULLIF(_rec->>'authority_key_id', '');
    v_issuer_common_name  := NULLIF(_rec->>'issuer_common_name', '');
    v_signature_algorithm := NULLIF(_rec->>'signature_algorithm', '');
    v_public_key_algorithm:= NULLIF(_rec->>'public_key_algorithm', '');
    v_crl_distribution_points := NULLIF(_rec->>'crl_distribution_points', '');

    v_not_after  := NULLIF(_rec->>'not_after', '')::timestamp;
    v_not_before := NULLIF(_rec->>'not_before', '')::timestamp;

    IF _rec ? 'is_ca' THEN
        v_is_ca := (_rec->>'is_ca')::boolean;
    ELSE
        v_is_ca := NULL;
    END IF;

    IF _rec ? 'tls_version' THEN
        v_tls_version := NULLIF(_rec->>'tls_version', '')::integer;
    ELSE
        v_tls_version := NULL;
    END IF;

    RETURN public.tlscertificate_upsert(
        v_serial_number,
        v_subject_common_name,
        v_is_ca,
        v_tls_version,
        v_key_usage,
        v_not_after,
        v_not_before,
        v_ext_key_usage,
        v_subject_key_id,
        v_authority_key_id,
        v_issuer_common_name,
        v_signature_algorithm,
        v_public_key_algorithm,
        v_crl_distribution_points
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by serial_number (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_get_id_by_serial_number(
    _serial_number text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.tlscertificate
    WHERE serial_number = _serial_number
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by serial_number
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_get_by_serial_number(
    _serial_number text
) RETURNS public.tlscertificate
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.tlscertificate
    WHERE serial_number = _serial_number
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by subject_common_name (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_find_by_subject_common_name(
    _subject_common_name text
) RETURNS SETOF public.tlscertificate
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.tlscertificate
    WHERE (CASE
             WHEN strpos(_subject_common_name, '%') > 0
               OR strpos(_subject_common_name, '_') > 0
               THEN subject_common_name ILIKE _subject_common_name
             ELSE subject_common_name = _subject_common_name
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.tlscertificate
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.tlscertificate
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a TLSCertificate AND its corresponding Entity.
-- Uses serial_number as the canonical natural key.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert_entity(
    _serial_number          text,
    _subject_common_name    text,
    _is_ca                  boolean DEFAULT NULL,
    _tls_version            integer DEFAULT NULL,
    _key_usage              text DEFAULT NULL,
    _not_after              timestamp without time zone DEFAULT NULL,
    _not_before             timestamp without time zone DEFAULT NULL,
    _ext_key_usage          text DEFAULT NULL,
    _subject_key_id         text DEFAULT NULL,
    _authority_key_id       text DEFAULT NULL,
    _issuer_common_name     text DEFAULT NULL,
    _signature_algorithm    text DEFAULT NULL,
    _public_key_algorithm   text DEFAULT NULL,
    _crl_distribution_points text DEFAULT NULL,
    _extra_attrs            jsonb  DEFAULT '{}'::jsonb,      -- caller-supplied extra attrs
    _etype_name             citext DEFAULT 'tlscertificate'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.tlscertificate%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _serial_number IS NULL OR _subject_common_name IS NULL THEN
        RAISE EXCEPTION
          'tlscertificate_upsert_entity requires non-NULL serial_number and subject_common_name';
    END IF;

    -- 1) Upsert into tlscertificate by serial_number.
    INSERT INTO public.tlscertificate (
        is_ca,
        tls_version,
        key_usage,
        not_after,
        not_before,
        ext_key_usage,
        serial_number,
        subject_key_id,
        authority_key_id,
        issuer_common_name,
        signature_algorithm,
        subject_common_name,
        public_key_algorithm,
        crl_distribution_points
    ) VALUES (
        _is_ca,
        _tls_version,
        _key_usage,
        _not_after,
        _not_before,
        _ext_key_usage,
        _serial_number,
        _subject_key_id,
        _authority_key_id,
        _issuer_common_name,
        _signature_algorithm,
        _subject_common_name,
        _public_key_algorithm,
        _crl_distribution_points
    )
    ON CONFLICT (serial_number) DO UPDATE
    SET
        is_ca                  = COALESCE(EXCLUDED.is_ca,                  tlscertificate.is_ca),
        tls_version            = COALESCE(EXCLUDED.tls_version,            tlscertificate.tls_version),
        key_usage              = COALESCE(EXCLUDED.key_usage,              tlscertificate.key_usage),
        not_after              = COALESCE(EXCLUDED.not_after,              tlscertificate.not_after),
        not_before             = COALESCE(EXCLUDED.not_before,             tlscertificate.not_before),
        ext_key_usage          = COALESCE(EXCLUDED.ext_key_usage,          tlscertificate.ext_key_usage),
        subject_key_id         = COALESCE(EXCLUDED.subject_key_id,         tlscertificate.subject_key_id),
        authority_key_id       = COALESCE(EXCLUDED.authority_key_id,       tlscertificate.authority_key_id),
        issuer_common_name     = COALESCE(EXCLUDED.issuer_common_name,     tlscertificate.issuer_common_name),
        signature_algorithm    = COALESCE(EXCLUDED.signature_algorithm,    tlscertificate.signature_algorithm),
        subject_common_name    = COALESCE(EXCLUDED.subject_common_name,    tlscertificate.subject_common_name),
        public_key_algorithm   = COALESCE(EXCLUDED.public_key_algorithm,   tlscertificate.public_key_algorithm),
        crl_distribution_points= COALESCE(EXCLUDED.crl_distribution_points,tlscertificate.crl_distribution_points),
        updated_at             = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the TLS certificate plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'serial_number',           v_row.serial_number,
            'subject_common_name',     v_row.subject_common_name,
            'is_ca',                   v_row.is_ca,
            'tls_version',             v_row.tls_version,
            'key_usage',               v_row.key_usage,
            'not_after',               v_row.not_after,
            'not_before',              v_row.not_before,
            'ext_key_usage',           v_row.ext_key_usage,
            'subject_key_id',          v_row.subject_key_id,
            'authority_key_id',        v_row.authority_key_id,
            'issuer_common_name',      v_row.issuer_common_name,
            'signature_algorithm',     v_row.signature_algorithm,
            'public_key_algorithm',    v_row.public_key_algorithm,
            'crl_distribution_points', v_row.crl_distribution_points
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using serial_number as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                           -- e.g. 'tlscertificate'
        _natural_key := v_row.serial_number::citext,           -- canonical key
        _table_name  := 'tlscertificate'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map serial_number -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_get_entity_id_by_serial_number(
    _serial_number text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.tlscertificate c
    JOIN public.entity e
      ON e.table_name = 'tlscertificate'
     AND e.row_id     = c.id
    WHERE c.serial_number = _serial_number
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+TLSCertificate by serial_number
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_get_with_entity_by_serial_number(
    _serial_number text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    cert_row     public.tlscertificate
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        c
    FROM public.tlscertificate c
    JOIN public.entity e
      ON e.table_name = 'tlscertificate'
     AND e.row_id     = c.id
    WHERE c.serial_number = _serial_number
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.tlscertificate_upsert(
    text,
    text,
    boolean,
    integer,
    text,
    timestamp without time zone,
    timestamp without time zone,
    text,
    text,
    text,
    text,
    text,
    text,
    text
);
DROP FUNCTION IF EXISTS public.tlscertificate_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.tlscertificate_get_id_by_serial_number(text);
DROP FUNCTION IF EXISTS public.tlscertificate_get_by_serial_number(text);
DROP FUNCTION IF EXISTS public.tlscertificate_find_by_subject_common_name(text);
DROP FUNCTION IF EXISTS public.tlscertificate_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.tlscertificate_upsert_entity(
    text,
    text,
    boolean,
    integer,
    text,
    timestamp without time zone,
    timestamp without time zone,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    jsonb,
    citext
);
DROP FUNCTION IF EXISTS public.tlscertificate_get_entity_id_by_serial_number(text);
DROP FUNCTION IF EXISTS public.tlscertificate_get_with_entity_by_serial_number(text);

DROP INDEX IF EXISTS idx_tlscertificate_public_key_algorithm;
DROP INDEX IF EXISTS idx_tlscertificate_signature_algorithm;
DROP INDEX IF EXISTS idx_tlscertificate_issuer_common_name;
DROP INDEX IF EXISTS idx_tlscertificate_subject_common_name;
DROP INDEX IF EXISTS idx_tlscertificate_tls_version;
DROP INDEX IF EXISTS idx_tlscertificate_updated_at;
DROP INDEX IF EXISTS idx_tlscertificate_created_at;
DROP TABLE IF EXISTS public.tlscertificate;