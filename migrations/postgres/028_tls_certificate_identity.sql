-- +migrate Up

-- ============================================================================
-- OWASP Amass: a TLS certificate is identified by its issuer and serial
-- number, not its serial number alone.
--
-- RFC 5280 (section 4.1.2.2) makes a serial number unique per issuer only,
-- and self-signed device certificates commonly use 0 or 1: certificates of
-- unrelated hosts with the same serial were stored as one, the later
-- overwriting the earlier. The identity is now the serial number with the
-- issuer's common name and key identifier and the certificate's own key
-- identifier, all fields the Open Asset Model already has; one certificate
-- always carries the same values, so no certificate is split. The entity's
-- natural key becomes the same identity. Certificates already merged cannot
-- be told apart again and stay as they are.
-- ============================================================================

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_key(_serial_number text, _attrs jsonb) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $fn$
    SELECT _serial_number
        || '|' || lower(COALESCE(_attrs->>'issuer_common_name', ''))
        || '|' || lower(COALESCE(_attrs->>'authority_key_id', ''))
        || '|' || lower(COALESCE(_attrs->>'subject_key_id', ''))
$fn$;
-- +migrate StatementEnd

ALTER TABLE public.tlscertificate
  ADD COLUMN cert_key text GENERATED ALWAYS AS (public.tlscertificate_key(serial_number, attrs)) STORED;
ALTER TABLE public.tlscertificate DROP CONSTRAINT tlscertificate_serial_number_key;
CREATE UNIQUE INDEX tlscertificate_cert_key_uidx ON public.tlscertificate (cert_key);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_serial_number ON public.tlscertificate (serial_number);

UPDATE public.entity e SET natural_key = t.cert_key
FROM public.tlscertificate t
WHERE e.table_name = 'public.tlscertificate'::citext AND e.row_id = t.id AND e.natural_key <> t.cert_key;

-- touch_guard leaves cert_key out of its comparison: generated columns are
-- not computed yet when it runs
DROP TRIGGER IF EXISTS touch_guard ON public.tlscertificate;
CREATE TRIGGER touch_guard BEFORE UPDATE ON public.tlscertificate
  FOR EACH ROW EXECUTE FUNCTION public.touch_guard('{cert_key}');

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert(
    _serial_number       text,
    _subject_common_name text,
    _attrs               jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _serial_number IS NULL THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL serial_number';
    END IF;

    IF NOT (_attrs ? 'not_before') OR NOT (_attrs ? 'not_after') THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL not_before and not_after';
    END IF;

    INSERT INTO public.tlscertificate (
        serial_number, subject_common_name, attrs
    ) VALUES (
        _serial_number, COALESCE(_subject_common_name, ''), _attrs
    )
    ON CONFLICT (cert_key) DO UPDATE
    SET
        subject_common_name = COALESCE(NULLIF(EXCLUDED.subject_common_name, ''), tlscertificate.subject_common_name),
        attrs               = tlscertificate.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at          = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.tlscertificate
        WHERE cert_key = public.tlscertificate_key(_serial_number, _attrs);
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row bigint;
    v_key text;
BEGIN
    -- 1) Upsert into tlscertificate.
    v_row := public.tlscertificate_upsert_json(_rec);
    SELECT cert_key INTO v_key FROM public.tlscertificate WHERE id = v_row;

    -- 2) Upsert into entity via the generic helper, keyed by the identity.
    RETURN public.entity_upsert(
        _etype_name  := 'tlscertificate'::citext,
        _natural_key := v_key::citext,
        _table_name  := 'public.tlscertificate'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- +migrate Down

-- Serial numbers become unique again: of the certificates sharing one, the
-- most recently seen is kept.
DELETE FROM public.entity e USING public.tlscertificate t
WHERE e.table_name = 'public.tlscertificate'::citext AND e.row_id = t.id
  AND t.id IN (SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY serial_number
                                      ORDER BY updated_at DESC, id DESC) AS rn
                               FROM public.tlscertificate) x WHERE rn > 1);
DELETE FROM public.tlscertificate
WHERE id IN (SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY serial_number
                                    ORDER BY updated_at DESC, id DESC) AS rn
                             FROM public.tlscertificate) x WHERE rn > 1);

UPDATE public.entity e SET natural_key = t.serial_number
FROM public.tlscertificate t
WHERE e.table_name = 'public.tlscertificate'::citext AND e.row_id = t.id;

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_serial_number text;
    v_row           bigint;
BEGIN
    v_serial_number := NULLIF(_rec->>'serial_number', '');

    -- 1) Upsert into tlscertificate.
    v_row := public.tlscertificate_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'tlscertificate'::citext,
        _natural_key := v_serial_number::citext,
        _table_name  := 'public.tlscertificate'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert(
    _serial_number       text,
    _subject_common_name text,
    _attrs               jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _serial_number IS NULL THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL serial_number';
    END IF;

    IF NOT (_attrs ? 'not_before') OR NOT (_attrs ? 'not_after') THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL not_before and not_after';
    END IF;

    INSERT INTO public.tlscertificate (
        serial_number, subject_common_name, attrs
    ) VALUES (
        _serial_number, COALESCE(_subject_common_name, ''), _attrs
    )
    ON CONFLICT (serial_number) DO UPDATE
    SET
        subject_common_name = COALESCE(NULLIF(EXCLUDED.subject_common_name, ''), tlscertificate.subject_common_name),
        attrs               = tlscertificate.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at          = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.tlscertificate WHERE serial_number = _serial_number;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

DROP TRIGGER IF EXISTS touch_guard ON public.tlscertificate;
DROP INDEX IF EXISTS public.idx_tlscertificate_serial_number;
DROP INDEX IF EXISTS public.tlscertificate_cert_key_uidx;
ALTER TABLE public.tlscertificate DROP COLUMN cert_key;
ALTER TABLE public.tlscertificate ADD CONSTRAINT tlscertificate_serial_number_key UNIQUE (serial_number);
CREATE TRIGGER touch_guard BEFORE UPDATE ON public.tlscertificate
  FOR EACH ROW EXECUTE FUNCTION public.touch_guard();
DROP FUNCTION IF EXISTS public.tlscertificate_key(text, jsonb);
