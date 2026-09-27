#!/bin/bash
# quic-interop-runner entrypoint. Only the server role and the h3 test case are
# implemented; every other case exits 127 (unsupported) per the runner spec.
set -e
/setup.sh
if [ "$ROLE" != "server" ]; then
    echo "boltapi: client role not implemented"; exit 127
fi
case "$TESTCASE" in
    http3) ;;
    *) echo "boltapi: test case $TESTCASE not supported"; exit 127 ;;
esac
exec boltapi_quic_interop_server 443 /www 0.0.0.0 >> "${SERVER_LOGS:-/logs}/server.log" 2>&1
