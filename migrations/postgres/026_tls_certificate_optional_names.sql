-- +migrate Up

-- ============================================================================
-- OWASP Amass: TLS certificates without a subject or issuer common name.
-- Only the upsert function changes; the table and its data do not.
-- ============================================================================

-- Upsert by serial_number (scalar params). Returns the row id. The common
-- names may be empty: a certificate can name its subject only in the subject
-- alternative name extension (RFC 5280, section 4.2.1.6), and its issuer only
-- by other attributes.
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

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate Down

-- Upsert by serial_number (scalar params). Returns the row id.
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

    IF _subject_common_name IS NULL OR NOT (_attrs ? 'issuer_common_name') THEN
        RAISE EXCEPTION
          'tlscertificate_upsert requires non-NULL subject_common_name and issuer_common_name';
    END IF;

    IF NOT (_attrs ? 'not_before') OR NOT (_attrs ? 'not_after') THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL not_before and not_after';
    END IF;

    INSERT INTO public.tlscertificate (
        serial_number, subject_common_name, attrs
    ) VALUES (
        _serial_number, _subject_common_name, _attrs
    )
    ON CONFLICT (serial_number) DO UPDATE
    SET
        subject_common_name = COALESCE(EXCLUDED.subject_common_name, tlscertificate.subject_common_name),
        attrs               = tlscertificate.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at          = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd
