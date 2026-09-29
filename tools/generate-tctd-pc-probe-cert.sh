#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: generate-tctd-pc-probe-cert.sh OUTPUT_DIRECTORY" >&2
    exit 2
fi

output_dir=$1
cert="$output_dir/server-cert.pem"
key="$output_dir/server-key.pem"

if [[ -f $cert && -f $key ]]; then
    chmod 600 -- "$cert" "$key"
    exit 0
fi
if [[ -e $cert || -e $key ]]; then
    echo "Refusing to replace an incomplete TLS probe identity in $output_dir" >&2
    exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "OpenSSL is required to generate the local TLS probe identity." >&2
    exit 1
fi

mkdir -p -m 700 -- "$output_dir"
umask 077
openssl req \
    -x509 \
    -newkey ec \
    -pkeyopt ec_paramgen_curve:P-256 \
    -sha256 \
    -nodes \
    -days 7300 \
    -subj '/C=SE/ST=Skane/L=Malmo/O=Massive Entertainment/OU=Tech Ops/emailAddress=sre@massive.se' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'subjectKeyIdentifier=hash' \
    -addext 'authorityKeyIdentifier=keyid:always' \
    -keyout "$key" \
    -out "$cert" \
    >/dev/null 2>&1
chmod 600 -- "$cert" "$key"
echo "Generated local-only tctd-pc TLS probe identity: $cert"
