#!/bin/sh
# Regenerates the test CA and server certificates used by test/mta-sts/*-test.js.
# The certificates are valid for 100 years so the tests do not start failing when they age.
set -e
cd "$(dirname "$0")"
DAYS=36500

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days $DAYS -subj "/CN=mailauth MTA-STS test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem

leaf() {
    name=$1
    subject=$2
    san=$3
    openssl ecparam -name prime256v1 -genkey -noout -out "$name.key"
    openssl req -new -key "$name.key" -subj "$subject" -out "$name.csr"
    {
        echo "basicConstraints=CA:FALSE"
        echo "extendedKeyUsage=serverAuth"
        if [ -n "$san" ]; then echo "subjectAltName=$san"; fi
    } > "$name.ext"
    openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days $DAYS -extfile "$name.ext" -out "$name.pem"
    rm -f "$name.csr" "$name.ext"
}

leaf good "/CN=x" "DNS:mta-sts.example.test"
leaf wild "/CN=x" "DNS:*.example.test"
leaf cnonly "/CN=mta-sts.example.test" ""
leaf partial "/CN=x" "DNS:mta-*.example.test"
leaf wrong "/CN=x" "DNS:mta-sts.other.test"
leaf idn "/CN=x" "DNS:mta-sts.xn--r8jz45g.test"
rm -f ca.srl
