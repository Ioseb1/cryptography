# Task 2: ECC Signature Verification Documentation

## Task 2A: Generate ECC Keys

### Step 1: Key Generation
Generated ECC key pair using the **prime256v1** curve (also known as secp256r1 or NIST P-256).

**Curve Details:**
- **OpenSSL Name:** prime256v1
- **Standard Name:** secp256r1
- **NIST Name:** NIST P-256
- **Key Size:** 256 bits
- **Security Level:** ~128 bits

### Step 2: Key Files
**Python Script:** `task2_generate_keys.py`

**Usage:**
```bash
python task2_generate_keys.py
```

The script will:
1. Generate a private key using the prime256v1 curve
2. Derive the public key from the private key
3. Save the private key to `ecc_private_key.pem` (PEM format, PKCS8)
4. Save the public key to `ecc_public_key.pem` (PEM format, SubjectPublicKeyInfo)

**Output Files:**
- `ecc_private_key.pem` - Private key in PEM format
- `ecc_public_key.pem` - Public key in PEM format

### Key Format
- **Private Key:** PKCS8 format, unencrypted
- **Public Key:** SubjectPublicKeyInfo format (X.509)

---

## Task 2B: Sign and Verify a Message

### Step 1: Create Message File
Created `ecc.txt` containing:
```
Elliptic Curves are efficient.
```

### Step 2: Sign the Message
**Python Script:** `task2_sign.py`

**Usage:**
```bash
python task2_sign.py
```

The script will:
1. Read `ecc.txt`
2. Load the private key from `ecc_private_key.pem`
3. Sign the message using ECDSA with SHA-256 hash
4. Save the signature to `ecc_signature.bin`

**Signature Algorithm:**
- **Scheme:** ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Hash Function:** SHA-256
- **Curve:** prime256v1 (secp256r1)

**Output File:**
- `ecc_signature.bin` - Binary signature file

### Step 3: Verify the Signature
**Python Script:** `task2_verify.py`

**Usage:**
```bash
python task2_verify.py
```

The script will:
1. Read `ecc.txt`
2. Load the public key from `ecc_public_key.pem`
3. Load the signature from `ecc_signature.bin`
4. Verify the signature using ECDSA with SHA-256
5. Report whether the signature is valid

**Verification Result:**
- ✓ **Valid:** The message was signed by the holder of the private key and has not been tampered with
- ✗ **Invalid:** The signature does not match (message tampered with, wrong key, or corrupted signature)

---

## Complete Demo

**Python Script:** `task2_demo.py`

Run the complete demonstration:
```bash
python task2_demo.py
```

This script will:
1. Generate ECC key pair
2. Sign `ecc.txt`
3. Verify the signature (should succeed)
4. Test verification with a modified message (should fail)
5. Display summary of all operations

---

## Alternative: OpenSSL Commands (if available)

If OpenSSL CLI is available, the following commands can be used:

### Generate Keys:
```bash
# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out ecc_private_key.pem

# Extract public key
openssl ec -in ecc_private_key.pem -pubout -out ecc_public_key.pem
```

### Sign Message:
```bash
openssl dgst -sha256 -sign ecc_private_key.pem -out ecc_signature.bin ecc.txt
```

### Verify Signature:
```bash
openssl dgst -sha256 -verify ecc_public_key.pem -signature ecc_signature.bin ecc.txt
```

**Note:** OpenSSL's `dgst` command uses ECDSA when given an EC private key.

---

## Dependencies

The Python scripts use the `cryptography` library (same as Task 1):
```bash
pip install cryptography
```

Or install from requirements.txt:
```bash
pip install -r requirements.txt
```

---

## File Structure

After running all scripts, you should have:
```
.
├── ecc.txt                    # Original message
├── ecc_private_key.pem        # ECC private key
├── ecc_public_key.pem         # ECC public key
├── ecc_signature.bin          # Digital signature
├── task2_generate_keys.py     # Key generation script
├── task2_sign.py              # Signing script
├── task2_verify.py            # Verification script
└── task2_demo.py              # Complete demo script
```

---

## Technical Details

### ECDSA Signature Process

1. **Key Generation:**
   - Generate random private key `d` (256-bit integer)
   - Calculate public key `Q = d * G` where `G` is the generator point

2. **Signing:**
   - Hash the message: `h = SHA-256(message)`
   - Generate random nonce `k`
   - Calculate signature components `(r, s)` using elliptic curve operations
   - Output signature as DER-encoded pair `(r, s)`

3. **Verification:**
   - Hash the message: `h = SHA-256(message)`
   - Extract `(r, s)` from signature
   - Verify using public key and elliptic curve operations
   - Signature is valid if verification equation holds

### Security Properties

- **Non-repudiation:** Only the holder of the private key can create a valid signature
- **Integrity:** Any modification to the message will invalidate the signature
- **Authentication:** Verifying with the public key confirms the message origin

---

## Assumptions

1. **Curve Selection:** prime256v1 (secp256r1) is used as specified
2. **Hash Function:** SHA-256 is used for message hashing (standard for ECDSA)
3. **Key Format:** PEM format is used for keys (standard and human-readable)
4. **Signature Format:** Binary DER-encoded format (standard for ECDSA)
5. **No Password Protection:** Private key is stored unencrypted (for simplicity; in production, use password protection)

---

## Error Handling

The scripts check for:
- Missing input files (message, keys, signature)
- Invalid key formats
- Signature verification failures
- File I/O errors

All errors are reported with clear messages to help diagnose issues.

