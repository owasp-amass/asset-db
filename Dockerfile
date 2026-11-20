# Pin the major version: an unpinned postgres:latest silently rolls to the next
# major (18 -> 19), whose Docker image will not start on an existing data
# directory from the prior major without a pg_upgrade, breaking live deployments.
FROM postgres:18
RUN mkdir -p /docker-entrypoint-initdb.d
COPY ./initdb-assetdb.sh /docker-entrypoint-initdb.d/1_assetdb.sh
RUN chmod +x /docker-entrypoint-initdb.d/1_assetdb.sh
STOPSIGNAL SIGINT
EXPOSE 5432
HEALTHCHECK --interval=5s --timeout=5s --retries=10 \
  CMD pg_isready -U postgres -d postgres
