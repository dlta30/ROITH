#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
exec uvicorn app:app --host 127.0.0.1 --port 8080 --workers 1 --limit-concurrency 20 --timeout-keep-alive 5
