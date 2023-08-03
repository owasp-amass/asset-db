# User Guide

## Postgres

This project relies upon several Postgres features that require elevated privileges.
If you are configuring this in an environment where you do not possess these privileges,
please work with your DBA to configure a new database in the following way:

```sql
-- Create a new database to store assets and relations.
CREATE DATABASE assetdb;

-- Create a user
CREATE USER your_username WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON SCHEMA assetdb TO your_username;

-- set the timezone to UTC
ALTER DATABASE assetdb SET timezone TO 'UTC';

```

Login to `assetdb` as  `your_username` and run the following commands:

```sql
-- Enable the pg_trgm extension for trigram matching support
CREATE EXTENSION pg_trgm;
```
