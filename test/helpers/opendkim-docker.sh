#!/bin/sh
# Runs OpenDKIM in a Debian container, for systems without an OpenDKIM package (macOS):
#   OPENDKIM=test/helpers/opendkim-docker.sh npm test
# The working directory is mounted at the same path, test/helpers/opendkim.ts keeps every file
# it passes to OpenDKIM there.
set -e

IMAGE=mailauth-opendkim-test

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    printf 'FROM debian:trixie-slim\nRUN apt-get update && apt-get install -y --no-install-recommends opendkim && rm -rf /var/lib/apt/lists/*\n' |
        docker build -q -t "$IMAGE" - >/dev/null
fi

exec docker run --rm -v "$PWD:$PWD" -w "$PWD" "$IMAGE" opendkim "$@"
