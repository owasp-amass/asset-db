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
CREATE INDEX IF NOT EXISTS idx_fundstransfer_created_at ON public.fundstransfer(created_at);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_updated_at ON public.fundstransfer(updated_at);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_amount ON public.fundstransfer(amount);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_reference_number ON public.fundstransfer(reference_number);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_currency ON public.fundstransfer(currency);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_transfer_method ON public.fundstransfer(transfer_method);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_exchange_rate ON public.fundstransfer(exchange_rate);

COMMIT;

-- +migrate Down

DROP INDEX IF EXISTS idx_fundstransfer_exchange_rate;
DROP INDEX IF EXISTS idx_fundstransfer_transfer_method;
DROP INDEX IF EXISTS idx_fundstransfer_currency;
DROP INDEX IF EXISTS idx_fundstransfer_reference_number;
DROP INDEX IF EXISTS idx_fundstransfer_amount;
DROP INDEX IF EXISTS idx_fundstransfer_updated_at;
DROP INDEX IF EXISTS idx_fundstransfer_created_at;
DROP TABLE IF EXISTS public.fundstransfer;