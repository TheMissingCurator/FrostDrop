#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
    echo "Usage: generate-tctd-echo-identity.sh BOOTSTRAP_IDENTITY OUTPUT_DIRECTORY" >&2
    exit 2
fi
ca_dir=$1
output_dir=$2
cert="$output_dir/server-cert.pem"
key="$output_dir/server-key.pem"
if [[ -f $cert && -f $key ]]; then
    openssl verify -CAfile "$ca_dir/server-cert.pem" "$cert" >/dev/null
    chmod 700 -- "$output_dir"
    chmod 600 -- "$cert" "$key"
    exit 0
fi
if [[ -e $cert || -e $key ]]; then
    echo "Refusing to overwrite an incomplete echo identity: $output_dir" >&2
    exit 1
fi
umask 077
mkdir -p -m 700 -- "$output_dir"
chmod 700 -- "$output_dir"
request_dir=$(mktemp -d -p /tmp project-isac-echo-cert.XXXXXXXX)
trap 'rm -rf -- "$request_dir"' EXIT
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj '/O=Project ISAC/CN=ISAC Local Echo' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=serverAuth' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "$key" -out "$request_dir/request.pem" >/dev/null 2>&1
serial=$(openssl rand -hex 16)
openssl x509 -req -in "$request_dir/request.pem" \
    -CA "$ca_dir/server-cert.pem" -CAkey "$ca_dir/server-key.pem" \
    -set_serial "0x$serial" -days 365 -sha256 -copy_extensions copy \
    -out "$cert" >/dev/null 2>&1
openssl verify -CAfile "$ca_dir/server-cert.pem" "$cert" >/dev/null
chmod 600 -- "$cert" "$key"
echo "Generated local echo leaf signed by Project ISAC bootstrap CA: $cert"
