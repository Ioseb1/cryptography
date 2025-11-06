#!/bin/bash
# OpenSSL TLS/HTTPS Inspection Script
# This script connects to an HTTPS website and extracts certificate information

# Default website (can be changed)
WEBSITE=${1:-"www.google.com"}
PORT=443

echo "=========================================="
echo "TLS/HTTPS Certificate Inspection"
echo "=========================================="
echo "Connecting to: $WEBSITE:$PORT"
echo ""

# 1. Connect and show full certificate chain
echo "=== Full Certificate Chain ==="
openssl s_client -connect $WEBSITE:$PORT -showcerts < /dev/null 2>&1 | tee certificate_chain.txt
echo ""

# 2. Extract server certificate only
echo "=== Server Certificate (PEM format) ==="
openssl s_client -connect $WEBSITE:$PORT -showcerts < /dev/null 2>&1 | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | head -n 25 > server_certificate.pem
cat server_certificate.pem
echo ""

# 3. Certificate details (issuer, validity, subject)
echo "=== Certificate Details ==="
openssl s_client -connect $WEBSITE:$PORT < /dev/null 2>&1 | openssl x509 -noout -text -in - 2>/dev/null || \
openssl s_client -connect $WEBSITE:$PORT < /dev/null 2>&1 | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | openssl x509 -noout -text > certificate_details.txt
cat certificate_details.txt
echo ""

# 4. Certificate summary (issuer, subject, dates)
echo "=== Certificate Summary ==="
echo "Subject:"
openssl s_client -connect $WEBSITE:$PORT < /dev/null 2>&1 | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | openssl x509 -noout -subject 2>/dev/null || echo "Unable to extract subject"
echo ""
echo "Issuer:"
openssl s_client -connect $WEBSITE:$PORT < /dev/null 2>&1 | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | openssl x509 -noout -issuer 2>/dev/null || echo "Unable to extract issuer"
echo ""
echo "Validity:"
openssl s_client -connect $WEBSITE:$PORT < /dev/null 2>&1 | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | openssl x509 -noout -dates 2>/dev/null || echo "Unable to extract dates"
echo ""

# 5. Cipher suite information
echo "=== Cipher Suite Information ==="
openssl s_client -connect $WEBSITE:$PORT < /dev/null 2>&1 | grep -i "cipher\|protocol" | tee cipher_suite.txt
echo ""

# 6. Certificate fingerprint
echo "=== Certificate Fingerprint ==="
openssl s_client -connect $WEBSITE:$PORT < /dev/null 2>&1 | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | openssl x509 -noout -fingerprint -sha256 2>/dev/null || echo "Unable to extract fingerprint"
echo ""

echo "=========================================="
echo "Inspection complete. Files created:"
echo "  - certificate_chain.txt"
echo "  - server_certificate.pem"
echo "  - certificate_details.txt"
echo "  - cipher_suite.txt"
echo "=========================================="

