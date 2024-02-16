FROM postgres:latest
RUN mkdir -p /docker-entrypoint-initdb.d
COPY ./initdb-assetdb.sh /docker-entrypoint-initdb.d/1_assetdb.sh
RUN chmod +x /docker-entrypoint-initdb.d/1_assetdb.sh
STOPSIGNAL SIGINT
EXPOSE 5432
HEALTHCHECK --interval=5s --timeout=5s --retries=10 \
  CMD pg_isready -U postgres -d postgres
