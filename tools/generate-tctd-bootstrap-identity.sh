#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: generate-tctd-bootstrap-identity.sh OUTPUT_DIRECTORY" >&2
    exit 2
fi

output_dir=$1
cert="$output_dir/server-cert.pem"
key="$output_dir/server-key.pem"
if [[ -f $cert && -f $key ]]; then
    chmod 700 -- "$output_dir"
    chmod 600 -- "$cert" "$key"
    exit 0
fi
if [[ -e $cert || -e $key ]]; then
    echo "Refusing to overwrite an incomplete bootstrap identity: $output_dir" >&2
    exit 1
fi

umask 077
mkdir -p -m 700 -- "$output_dir"
chmod 700 -- "$output_dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -sha256 -nodes -days 7300 \
    -subj '/O=Project ISAC/OU=Local Development/CN=ISAC Local Bootstrap CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -addext 'subjectKeyIdentifier=hash' \
    -addext 'authorityKeyIdentifier=keyid:always' \
    -keyout "$key" -out "$cert" >/dev/null 2>&1
chmod 600 -- "$cert" "$key"
echo "Generated Project ISAC local bootstrap identity: $cert"
