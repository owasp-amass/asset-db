-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- FundsTransfer Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.fundstransfer (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  unique_id text NOT NULL UNIQUE,
  amount numeric NOT NULL,
  reference_number text,
  currency text,
  transfer_method text,
  exchange_date timestamp without time zone,
  exchange_rate numeric
);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_created_at
  ON public.fundstransfer(created_at);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_updated_at
  ON public.fundstransfer(updated_at);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_amount
  ON public.fundstransfer(amount);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_reference_number
  ON public.fundstransfer(reference_number);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_currency
  ON public.fundstransfer(currency);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_transfer_method
  ON public.fundstransfer(transfer_method);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_exchange_rate
  ON public.fundstransfer(exchange_rate);

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_upsert(
    _unique_id       text,
    _amount          numeric,
    _reference_number text DEFAULT NULL,
    _currency        text DEFAULT NULL,
    _transfer_method text DEFAULT NULL,
    _exchange_date   timestamp without time zone DEFAULT NULL,
    _exchange_rate   numeric DEFAULT NULL
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
        unique_id,
        amount,
        reference_number,
        currency,
        transfer_method,
        exchange_date,
        exchange_rate
    ) VALUES (
        _unique_id,
        _amount,
        _reference_number,
        _currency,
        _transfer_method,
        _exchange_date,
        _exchange_rate
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        amount           = EXCLUDED.amount,
        reference_number = COALESCE(EXCLUDED.reference_number, fundstransfer.reference_number),
        currency         = COALESCE(EXCLUDED.currency,         fundstransfer.currency),
        transfer_method  = COALESCE(EXCLUDED.transfer_method,  fundstransfer.transfer_method),
        exchange_date    = COALESCE(EXCLUDED.exchange_date,    fundstransfer.exchange_date),
        exchange_rate    = COALESCE(EXCLUDED.exchange_rate,    fundstransfer.exchange_rate),
        updated_at       = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys:
--   unique_id, amount, reference_number, currency, transfer_method,
--   exchange_date, exchange_rate
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id       text;
    v_amount          numeric;
    v_reference_number text;
    v_currency        text;
    v_transfer_method text;
    v_exchange_date   timestamp without time zone;
    v_exchange_rate   numeric;
BEGIN
    v_unique_id        := _rec->>'unique_id';
    v_amount           := NULLIF(_rec->>'amount', '')::numeric;
    v_reference_number := NULLIF(_rec->>'reference_number', '');
    v_currency         := NULLIF(_rec->>'currency', '');
    v_transfer_method  := NULLIF(_rec->>'transfer_method', '');
    v_exchange_date    := NULLIF(_rec->>'exchange_date', '')::timestamp;
    v_exchange_rate    := NULLIF(_rec->>'exchange_rate', '')::numeric;

    RETURN public.fundstransfer_upsert(
        v_unique_id,
        v_amount,
        v_reference_number,
        v_currency,
        v_transfer_method,
        v_exchange_date,
        v_exchange_rate
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by unique_id (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_get_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.fundstransfer
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_get_by_unique_id(
    _unique_id text
) RETURNS public.fundstransfer
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.fundstransfer
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by reference_number (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_find_by_reference_number(
    _reference_number text
) RETURNS SETOF public.fundstransfer
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.fundstransfer
    WHERE (CASE
             WHEN strpos(_reference_number, '%') > 0 OR strpos(_reference_number, '_') > 0
               THEN reference_number ILIKE _reference_number
             ELSE reference_number = _reference_number
           END)
    ORDER BY updated_at DESC, id DESC;
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
    SELECT *
    FROM public.fundstransfer
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a FundsTransfer AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_upsert_entity(
    _unique_id        text,
    _amount           numeric,
    _reference_number text DEFAULT NULL,
    _currency         text DEFAULT NULL,
    _transfer_method  text DEFAULT NULL,
    _exchange_date    timestamp without time zone DEFAULT NULL,
    _exchange_rate    numeric DEFAULT NULL,
    _extra_attrs      jsonb  DEFAULT '{}'::jsonb,        -- for caller-provided extra attributes
    _etype_name       citext DEFAULT 'fundstransfer'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.fundstransfer%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _unique_id IS NULL OR _amount IS NULL THEN
        RAISE EXCEPTION 'fundstransfer_upsert_entity requires non-NULL unique_id and amount';
    END IF;

    -- 1) Upsert into fundstransfer by unique_id.
    INSERT INTO public.fundstransfer (
        unique_id,
        amount,
        reference_number,
        currency,
        transfer_method,
        exchange_date,
        exchange_rate
    ) VALUES (
        _unique_id,
        _amount,
        _reference_number,
        _currency,
        _transfer_method,
        _exchange_date,
        _exchange_rate
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        amount           = EXCLUDED.amount,
        reference_number = COALESCE(EXCLUDED.reference_number, fundstransfer.reference_number),
        currency         = COALESCE(EXCLUDED.currency,         fundstransfer.currency),
        transfer_method  = COALESCE(EXCLUDED.transfer_method,  fundstransfer.transfer_method),
        exchange_date    = COALESCE(EXCLUDED.exchange_date,    fundstransfer.exchange_date),
        exchange_rate    = COALESCE(EXCLUDED.exchange_rate,    fundstransfer.exchange_rate),
        updated_at       = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the fundstransfer plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'unique_id',        v_row.unique_id,
            'amount',           v_row.amount,
            'reference_number', v_row.reference_number,
            'currency',         v_row.currency,
            'transfer_method',  v_row.transfer_method,
            'exchange_date',    v_row.exchange_date,
            'exchange_rate',    v_row.exchange_rate
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert).
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                     -- e.g. 'fundstransfer'
        _natural_key := v_row.unique_id::citext,         -- canonical key
        _table_name  := 'fundstransfer'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map unique_id -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_get_entity_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.fundstransfer f
    JOIN public.entity e
      ON e.table_name = 'fundstransfer'
     AND e.row_id     = f.id
    WHERE f.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+FundsTransfer by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_get_with_entity_by_unique_id(
    _unique_id text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    transfer     public.fundstransfer
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        f
    FROM public.fundstransfer f
    JOIN public.entity e
      ON e.table_name = 'fundstransfer'
     AND e.row_id     = f.id
    WHERE f.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.fundstransfer_upsert(
    text,
    numeric,
    text,
    text,
    text,
    timestamp without time zone,
    numeric
);
DROP FUNCTION IF EXISTS public.fundstransfer_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.fundstransfer_get_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.fundstransfer_get_by_unique_id(text);
DROP FUNCTION IF EXISTS public.fundstransfer_find_by_reference_number(text);
DROP FUNCTION IF EXISTS public.fundstransfer_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.fundstransfer_upsert_entity(
    text,
    numeric,
    text,
    text,
    text,
    timestamp without time zone,
    numeric,
    jsonb,
    citext
);
DROP FUNCTION IF EXISTS public.fundstransfer_get_entity_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.fundstransfer_get_with_entity_by_unique_id(text);

DROP INDEX IF EXISTS idx_fundstransfer_exchange_rate;
DROP INDEX IF EXISTS idx_fundstransfer_transfer_method;
DROP INDEX IF EXISTS idx_fundstransfer_currency;
DROP INDEX IF EXISTS idx_fundstransfer_reference_number;
DROP INDEX IF EXISTS idx_fundstransfer_amount;
DROP INDEX IF EXISTS idx_fundstransfer_updated_at;
DROP INDEX IF EXISTS idx_fundstransfer_created_at;
DROP TABLE IF EXISTS public.fundstransfer;