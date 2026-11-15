# User Guide

## Postgres

This project relies upon several Postgres features that require elevated privileges.
If you plan to use a _superuser_ when running migrations and working with the database,
you can skip this section.

It is best practice to _not_ use a superuser in most enterprise environments.
For this reason, if you are configuring this in an environment
where you do not possess these privileges,
please work with your DBA to configure a new database in the following way:

```sql
-- Create a new database to store assets and relations.
CREATE DATABASE IF NOT EXISTS assetdb;

-- set the timezone to UTC
ALTER DATABASE assetdb SET timezone TO 'UTC';
```

Reconnect to the `assetdb` database with the privileged user and run the following:

```sql

-- pg_trgm is required for to improve the performance of queries that use the LIKE operator.
-- If you already have pg_trgm installed (extensions are global), you can skip this step
-- If you don't know, you can run the following query to check:
-- SELECT * FROM pg_extension where extname = 'pg_trgm';

-- Install the pg_trgm extension on assetdb
CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA public;

-- Create a user
CREATE USER your_username WITH PASSWORD 'your_password';

-- on Postgres 15, the public schema is not available except to superusers.
GRANT USAGE ON schema public to your_username;

-- Grant create permissions to your user on the public schema.
GRANT CREATE ON schema public to your_username;

-- Grant table modification permissions to your user on the public schema.
GRANT ALL ON ALL TABLES IN SCHEMA public to your_username;

```

If you would like to keep the schema modifications separate from the collection user,
you can create a separate user for this purpose.

## Collection runs

Any tool that collects into the database, not only Amass, can record each
run: what it was asked to collect, when it started and ended, and how it
ended. Readers use runs to tell "not seen by a run that looked" apart from
"not looked for": an asset in a finished run's scope that was last seen
before the run started was not found by that run.

A run's scope is a list of Open Asset Model targets, each an asset type and
the asset's key (`{"type": "FQDN", "key": "example.com"}`,
`{"type": "Netblock", "key": "192.0.2.0/24"}`). Its status is `running`,
`finished` (all its work done), `stopped` (ended early) or `failed`. Only
finished runs should be read as complete. Times are UTC.

From Go, with any of the PostgreSQL, SQLite or Neo4j repositories:

```go
runs, ok := repo.(repository.RunRecorder)
if ok {
	run, err := runs.StartRun(ctx, &types.CollectionRun{
		Tool:        "my-scanner",
		ToolVersion: "1.2.0",
		StartedAt:   time.Now().UTC(),
		Scope:       []types.RunTarget{{Type: oam.FQDN, Key: "example.com"}},
		Metadata:    map[string]any{"mode": "passive"},
	})
	// ... collect ...
	_, err = runs.FinishRun(ctx, run.ID, types.RunFinished, time.Time{})
}
```

Tools in other languages can write the `collection_run` table directly
(PostgreSQL and SQLite) once the migrations have run: `run_id` is any unique
text (a UUID), `scope` and `metadata` are JSON, and SQLite stores times as
`YYYY-MM-DD HH:MM:SS.SSS` text in UTC. On Neo4j a run is a `CollectionRun`
node with the same properties and `scope` and `metadata` as JSON strings.

## Address ranges

`repository.IPRangeReader` finds the stored addresses inside a range
(`FindAddressesInRange`, up to 1,000 at a time, reporting when there are
more) and the stored netblocks that contain an address, most specific first
(`FindNetblocksContaining`). PostgreSQL uses GiST indexes on the `inet` and
`cidr` columns; SQLite and Neo4j keep fixed-width range keys beside each
address and netblock, filled in when the database is opened, so existing
data needs no manual step.
