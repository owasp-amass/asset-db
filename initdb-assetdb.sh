#!/bin/bash
set -e

# add single quotes around the Amass password
export TEMPPASS="'$AMASS_PASSWORD'"

# create the Amass user and asset-db database within PostgreSQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    \getenv assetdb AMASS_DB
    \getenv username AMASS_USER
    \getenv password TEMPPASS
    CREATE DATABASE :assetdb;
    ALTER DATABASE :assetdb SET timezone TO 'UTC';
    CREATE USER :username WITH PASSWORD :password;
EOSQL

# within the new asset-db, install the trigram matching 
# extension and grant privileges to the Amass user
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$AMASS_DB" <<-EOSQL
    \getenv username AMASS_USER
    CREATE EXTENSION pg_trgm SCHEMA public;
	GRANT USAGE ON SCHEMA public TO :username;
    GRANT CREATE ON SCHEMA public TO :username;
    GRANT ALL ON ALL TABLES IN SCHEMA public TO :username;

    CREATE OR REPLACE FUNCTION names_to_addrs(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE) RETURNS TABLE(fqdn TEXT, ip_addr TEXT) AS \$BODY\$ 
    DECLARE
        _name TEXT;
        _names TEXT[];
        _var_r RECORD;
        _to TIMESTAMP;
        _from TIMESTAMP;
    BEGIN
        _to = \$3;
        _from = \$2;
        _names = string_to_array(\$1, ',');

        FOR _var_r IN (
            SELECT srvs.content->>'name' AS "name", ips.content->>'address' AS "addr" 
            FROM ((((assets AS fqdns INNER JOIN relations AS r1 ON fqdns.id = r1.from_asset_id) 
            INNER JOIN assets AS srvs ON r1.to_asset_id = srvs.id) INNER JOIN relations AS r2 ON srvs.id = 
            r2.from_asset_id) INNER JOIN assets AS ips ON r2.to_asset_id = ips.id) 
            WHERE fqdns.type = 'FQDN' AND srvs.type = 'FQDN' AND ips.type = 'IPAddress' 
            AND r1.type IN ('srv_record','ns_record','mx_record') AND r2.type IN ('a_record','aaaa_record') 
            AND r1.last_seen >= _from AND r1.last_seen <= _to AND r2.last_seen >= _from AND r2.last_seen <= _to 
            AND fqdns.content->>'name' = ANY(_names)
        ) LOOP fqdn = _var_r.name;
            ip_addr = _var_r.addr;
            _names = array_remove(_names, _var_r.name);
            RETURN NEXT;
        END LOOP;

        FOR _var_r IN (
            SELECT fqdns.content->>'name' AS "name", ips.content->>'address' AS "addr" 
            FROM ((assets AS fqdns 
            INNER JOIN relations ON fqdns.id = relations.from_asset_id) 
            INNER JOIN assets AS ips ON relations.to_asset_id = ips.id) 
            WHERE fqdns.type = 'FQDN' AND ips.type = 'IPAddress' 
            AND relations.type IN ('a_record', 'aaaa_record') 
            AND relations.last_seen >= _from AND relations.last_seen <= _to 
            AND fqdns.content->>'name' = ANY(_names)
        ) LOOP fqdn = _var_r.name;
            ip_addr = _var_r.addr;
            _names = array_remove(_names, _var_r.name);
            RETURN NEXT;
        END LOOP;

        FOREACH _name IN ARRAY _names LOOP
            FOR _var_r IN (
                WITH RECURSIVE traverse_cname(_fqdn) AS ( 
                VALUES(_name) 
                UNION 
                SELECT cnames.content->>'name' FROM ((assets AS fqdns 
                INNER JOIN relations ON fqdns.id = relations.from_asset_id) 
                INNER JOIN assets AS cnames ON relations.to_asset_id = cnames.id), traverse_cname 
                WHERE fqdns.type = 'FQDN' AND cnames.type = 'FQDN' 
                AND relations.last_seen >= _from AND relations.last_seen <= _to 
                AND relations.type = 'cname_record' AND fqdns.content->>'name' = traverse_cname._fqdn) 
                SELECT fqdns.content->>'name' AS "name", ips.content->>'address' AS "addr" 
                FROM ((assets AS fqdns INNER JOIN relations ON fqdns.id = relations.from_asset_id) 
                INNER JOIN assets AS ips ON relations.to_asset_id = ips.id) 
                WHERE fqdns.type = 'FQDN' AND ips.type = 'IPAddress' 
                AND relations.last_seen >= _from AND relations.last_seen <= _to 
                AND relations.type IN ('a_record', 'aaaa_record') 
                AND fqdns.content->>'name' IN (SELECT _fqdn FROM traverse_cname)
            ) LOOP fqdn = _name;
                ip_addr = _var_r.addr;
                RETURN NEXT;
            END LOOP;
        END LOOP;
    END
    \$BODY\$ LANGUAGE plpgsql IMMUTABLE STRICT;
EOSQL
