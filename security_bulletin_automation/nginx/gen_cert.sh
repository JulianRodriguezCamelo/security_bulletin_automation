#!/usr/bin/env bash
# Genera certificado autofirmado para desarrollo / intranet.
# Para producción pública usa Let's Encrypt: certbot --nginx
set -e
OUT="$(dirname "$0")/certs"
mkdir -p "$OUT"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$OUT/key.pem" \
  -out    "$OUT/cert.pem" \
  -subj "/C=CO/ST=Bogota/O=CYWEX/CN=argos.local"
echo "Certificado generado en $OUT/"
