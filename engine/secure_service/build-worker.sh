#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
command -v podman >/dev/null 2>&1 || { echo "Podman is required." >&2; exit 1; }
rootless=$(podman info --format '{{.Host.Security.Rootless}}')
[ "$rootless" = "true" ] || { echo "Refusing to build/run the worker with rootful Podman. Configure rootless Podman first." >&2; exit 1; }
podman build --pull=always -f Dockerfile.worker -t localhost/roith-worker:1.0 .
