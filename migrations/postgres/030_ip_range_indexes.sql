-- +migrate Up

-- ============================================================================
-- OWASP Amass: IP range searches (PostgreSQL 13+)
-- GiST indexes let repository.IPRangeReader find the addresses within a
-- range (<<=) and the netblocks containing an address (>>=).
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_ipaddress_ip_address_gist ON public.ipaddress USING gist (ip_address inet_ops);
CREATE INDEX IF NOT EXISTS idx_netblock_cidr_gist ON public.netblock USING gist (netblock_cidr inet_ops);

-- +migrate Down

DROP INDEX IF EXISTS public.idx_netblock_cidr_gist;
DROP INDEX IF EXISTS public.idx_ipaddress_ip_address_gist;
