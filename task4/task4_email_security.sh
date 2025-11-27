set -e  # Exit on error

echo "=========================================="
echo "Email Encryption and Signature Simulation"
echo "=========================================="
echo ""

# Check if GPG is installed
if ! command -v gpg &> /dev/null; then
    echo "ERROR: GPG (GnuPG) is not installed."
    echo "Please install GPG:"
    echo "  - Linux: sudo apt-get install gnupg"
    echo "  - macOS: brew install gnupg"
    echo "  - Windows: Download from https://www.gnupg.org/download/"
    exit 1
fi

echo "GPG version:"
gpg --version | head -n 1
echo ""

# Clean up any existing keys from previous runs (optional)
echo "Cleaning up any existing test keys..."
gpg --batch --yes --delete-secret-keys "Alice <alice@example.com>" 2>/dev/null || true
gpg --batch --yes --delete-keys "Alice <alice@example.com>" 2>/dev/null || true
gpg --batch --yes --delete-secret-keys "Bob <bob@example.com>" 2>/dev/null || true
gpg --batch --yes --delete-keys "Bob <bob@example.com>" 2>/dev/null || true

echo ""
echo "=========================================="
echo "Step 1: Generate GPG Key Pair for Alice"
echo "=========================================="

# Generate Alice's key pair (non-interactive)
gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Alice
Name-Email: alice@example.com
Expire-Date: 0
Passphrase: alicepass123
%commit
EOF

echo "Alice's key pair generated successfully!"
echo ""

echo "=========================================="
echo "Step 2: Generate GPG Key Pair for Bob"
echo "=========================================="

# Generate Bob's key pair (non-interactive)
gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Bob
Name-Email: bob@example.com
Expire-Date: 0
Passphrase: bobpass123
%commit
EOF

echo "Bob's key pair generated successfully!"
echo ""

echo "=========================================="
echo "Step 3: Export Public and Private Keys"
echo "=========================================="

# Export Alice's public key
echo "Exporting Alice's public key..."
gpg --armor --export alice@example.com > public.asc
echo "Saved public.asc (Alice's public key)"

# Export Alice's private key
echo "Exporting Alice's private key..."
echo "alicepass123" | gpg --batch --yes --pinentry-mode loopback --armor --export-secret-keys alice@example.com > private.key
echo "Saved private.key (Alice's private key)"

# Export Bob's public key (for Alice to encrypt to)
echo "Exporting Bob's public key..."
gpg --armor --export bob@example.com > bob_public.asc
echo "Saved bob_public.asc (Bob's public key)"
echo ""

echo "=========================================="
echo "Step 4: Alice Signs and Encrypts Message"
echo "=========================================="

# Alice encrypts and signs the message for Bob
echo "Alice encrypting and signing message for Bob..."
echo "alicepass123" | gpg --batch --yes --pinentry-mode loopback --armor --encrypt --sign --recipient bob@example.com --default-key alice@example.com --output signed_message.asc original_message.txt
echo "Created signed_message.asc (encrypted and signed message)"
echo ""

echo "=========================================="
echo "Step 5: Bob Decrypts and Verifies Message"
echo "=========================================="

# Bob decrypts the message
echo "Bob decrypting message..."
echo "bobpass123" | gpg --batch --yes --pinentry-mode loopback --decrypt signed_message.asc > decrypted_message.txt
echo "Created decrypted_message.txt"

# Bob verifies the signature
echo "Bob verifying signature..."
echo "bobpass123" | gpg --batch --yes --pinentry-mode loopback --verify signed_message.asc 2>&1 | tee signature_verification_output.txt || true
echo ""

echo "=========================================="
echo "Step 6: List Keys"
echo "=========================================="
echo "Alice's keys:"
gpg --list-keys alice@example.com
echo ""
echo "Bob's keys:"
gpg --list-keys bob@example.com
echo ""

echo "=========================================="
echo "Task 4 completed successfully!"
echo "=========================================="
echo ""
echo "Generated files:"
echo "  - public.asc: Alice's public key"
echo "  - private.key: Alice's private key"
echo "  - signed_message.asc: Encrypted and signed message"
echo "  - decrypted_message.txt: Decrypted message"
echo "  - signature_verification_output.txt: Signature verification output"

