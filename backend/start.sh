#!/usr/bin/env sh
# Web entrypoint. Railway should inject PORT for a web service, but in this
# environment PORT has been arriving as 5432 (the PostgreSQL port), which a
# web server must never bind to. Guard against that explicitly.

PORT_TO_USE="${PORT:-8000}"

# Reject the Postgres port and any obviously-invalid value; fall back to 8000.
case "$PORT_TO_USE" in
  5432|"" )
    echo "[start] WARNING: PORT='$PORT' is invalid for a web server (5432 is PostgreSQL). Falling back to 8000."
    PORT_TO_USE=8000
    ;;
  *[!0-9]* )
    echo "[start] WARNING: PORT='$PORT' is not numeric. Falling back to 8000."
    PORT_TO_USE=8000
    ;;
esac

echo "[start] Launching uvicorn on 0.0.0.0:${PORT_TO_USE} (raw PORT env was '${PORT}')"
exec uvicorn main:app --host 0.0.0.0 --port "${PORT_TO_USE}"
