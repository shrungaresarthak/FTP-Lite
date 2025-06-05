#!/usr/bin/env bash
set -x
echo "[AUTOTEST] Starting FTP-Lite server on $1:$2 ..."

# Launch the server.  Do NOT background it (so we inherit stdout/stderr),
# pytest will start it and then terminate it later.
python3 server.py --host "$1" --port "$2" --cert "$3" --key "$4"
