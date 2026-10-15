FROM couchdb:3.5.2.1

USER root

RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

USER couchdb
