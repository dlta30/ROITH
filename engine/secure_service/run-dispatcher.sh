#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
exec python dispatcher.py --poll-seconds 2
