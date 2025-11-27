echo "=========================================="
echo "TLS Communication Inspection & Analysis"
echo "=========================================="
echo ""

# Website to analyze (default: google.com)
WEBSITE="${1:-google.com}"
PORT="${2:-443}"

echo "Connecting to $WEBSITE:$PORT..."
echo ""

# Connect and show certificate chain, cipher suite, and TLS version
openssl s_client -connect ${WEBSITE}:${PORT} -showcerts < /dev/null 2>&1 | tee tls_output.txt

echo ""
echo "=========================================="
echo "Analysis complete. Output saved to tls_output.txt"
echo "=========================================="

