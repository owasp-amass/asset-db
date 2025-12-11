-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- FundsTransfer Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.fundstransfer (
  id               bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at       timestamp without time zone NOT NULL DEFAULT now(),
  updated_at       timestamp without time zone NOT NULL DEFAULT now(),
  unique_id        text NOT NULL UNIQUE,
  amount           numeric NOT NULL,
  reference_number text,
  attrs            jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_created_at ON public.fundstransfer (created_at);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_updated_at ON public.fundstransfer (updated_at);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_amount ON public.fundstransfer (amount);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_reference_number ON public.fundstransfer (reference_number);

-- Upsert an FundsTransfer AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id text;
    v_row       bigint;
BEGIN
    v_unique_id := (_rec->>'unique_id');

    -- 1) Upsert into fundstransfer.
    v_row := public.fundstransfer_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'fundstransfer'::citext,
        _natural_key := v_unique_id::citext,
        _table_name  := 'public.fundstransfer'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_upsert(
    _unique_id        text,
    _amount           numeric,
    _reference_number text DEFAULT NULL,
    _attrs            jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _amount IS NULL THEN
        RAISE EXCEPTION 'fundstransfer_upsert requires non-NULL unique_id and amount';
    END IF;

    INSERT INTO public.fundstransfer (
        unique_id, amount, reference_number, attrs
    ) VALUES (
        _unique_id, _amount, _reference_number, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        amount           = EXCLUDED.amount,
        reference_number = COALESCE(EXCLUDED.reference_number, fundstransfer.reference_number),
        attrs            = fundstransfer.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at       = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id        text;
    v_amount           numeric;
    v_reference_number text;
    v_currency         text;
    v_transfer_method  text;
    v_exchange_date    timestamp without time zone;
    v_exchange_rate    numeric;
BEGIN
    v_unique_id        := NULLIF(_rec->>'unique_id', '');
    v_amount           := CASE
                            WHEN _rec ? 'amount' THEN (_rec->>'amount')::numeric
                            ELSE NULL
                          END;
    v_reference_number := (_rec->>'reference_number');
    v_currency         := NULLIF(_rec->>'currency', '');
    v_transfer_method  := NULLIF(_rec->>'transfer_method', '');
    v_exchange_date    := NULLIF(_rec->>'exchange_date', '')::timestamp;
    v_exchange_rate    := CASE
                            WHEN _rec ? 'exchange_rate' THEN (_rec->>'exchange_rate')::numeric
                            ELSE NULL
                          END;

    IF v_amount IS NOT NULL AND v_amount = 0 THEN
        v_amount := NULL;
    END IF;
    IF v_exchange_rate IS NOT NULL AND v_exchange_rate = 0 THEN
        v_exchange_rate := NULL;
    END IF;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'currency',        v_currency,
            'transfer_method', v_transfer_method,
            'exchange_date',   v_exchange_date,
            'exchange_rate',   v_exchange_rate,
        )
    ) || '{}'::jsonb;

    RETURN public.fundstransfer_upsert(
        v_unique_id,
        v_amount,
        v_reference_number,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_get_by_id(_row_id bigint)
RETURNS public.fundstransfer
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, unique_id, amount, reference_number, attrs
    FROM public.fundstransfer
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.fundstransfer
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, unique_id, amount, reference_number, attrs
    FROM public.fundstransfer
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.fundstransfer_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.fundstransfer_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.fundstransfer_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.fundstransfer_upsert(text, numeric, text, jsonb);
DROP FUNCTION IF EXISTS public.fundstransfer_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_fundstransfer_reference_number;
DROP INDEX IF EXISTS idx_fundstransfer_amount;
DROP INDEX IF EXISTS idx_fundstransfer_updated_at;
DROP INDEX IF EXISTS idx_fundstransfer_created_at;
DROP TABLE IF EXISTS public.fundstransfer;