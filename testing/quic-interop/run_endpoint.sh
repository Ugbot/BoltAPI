#!/bin/bash
# quic-interop-runner entrypoint (server role). Cases other than those listed
# exit 127 (unsupported) per the runner spec.
set -e
/setup.sh
if [ "$ROLE" != "server" ]; then
    echo "boltapi: client role not implemented"; exit 127
fi
opts=(--hq)
case "$TESTCASE" in
    handshake|transfer|multiplexing|resumption|http3|chacha20|keyupdate) ;;
    multiconnect|handshakeloss|transferloss|handshakecorruption|transfercorruption) ;;
    retry) opts+=(--retry) ;;
    zerortt) opts+=(--early-data) ;;
    *) echo "boltapi: test case $TESTCASE not supported"; exit 127 ;;
esac
if [ -f /certs/cert.pem ] && [ -f /certs/priv.key ]; then
    opts+=(--cert /certs/cert.pem --key /certs/priv.key)
fi
exec boltapi_quic_interop_server 443 /www 0.0.0.0 "${opts[@]}" \
    >> "${SERVER_LOGS:-/logs}/server.log" 2>&1
