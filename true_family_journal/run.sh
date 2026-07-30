#!/bin/sh
set -eu

umask 077
exec python3 -I -B /app/server.py
