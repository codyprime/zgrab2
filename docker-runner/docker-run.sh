#!/usr/bin/env bash

# Runs the zgrab2_runner docker image (built with docker-runner/build-runner.sh)
# Links the runner image to the targetted container with the hostname alias "target",
# then scans target using the arguments to the script.

: "${CONTAINER_NAME:?}"

set -e

MOUNT=""
if [ -n "$MOUNT_HOST" ]; then
    : "${MOUNT_CONTAINER:?}"
    MOUNT="-v $MOUNT_HOST:$MOUNT_CONTAINER"
fi

docker run --rm --link $CONTAINER_NAME:target $MOUNT -e ZGRAB_TARGET=target zgrab2_runner $@
