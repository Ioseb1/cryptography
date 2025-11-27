# Secure File Exchange Using RSA + AES

## Overview
This project demonstrates a hybrid encryption protocol for secure file exchange between Alice and Bob. The system combines RSA (asymmetric encryption) for key exchange and AES (symmetric encryption) for efficient bulk data encryption, along with SHA-256 for integrity verification.

## Encryption/Decryption Flow

### Step-by-Step Process

#### 1. Key Generation (Bob)
- Bob generates an RSA-2048 key pair
- **Public Key** (`public.pem`): Shared with Alice, used for encryption
- **Private Key** (`private.pem`): Kept secret by Bob, used for decryption

#### 2. File Preparation (Alice)
- Alice reads the plaintext file `alice_message.txt`
- Computes SHA-256 hash of the original file for later integrity verification
- This hash serves as a fingerprint to detect any tampering

#### 3. Encryption (Alice)
- **AES Key Generation**: Alice generates a random 256-bit (32-byte) AES key
- **IV Generation**: Alice generates a random 16-byte Initialization Vector (IV)
- **File Encryption**: 
  - Encrypts `alice_message.txt` using AES-256-CBC mode
  - Uses the generated AES key and IV
  - Saves encrypted data to `encrypted_file.bin` (IV prepended)
- **Key Encryption**:
  - Encrypts the AES key using Bob's RSA public key
  - Uses OAEP padding with SHA-256
  - Saves encrypted key to `aes_key_encrypted.bin`

#### 4. Transmission
- Alice sends to Bob:
  - `encrypted_file.bin` (encrypted file)
  - `aes_key_encrypted.bin` (encrypted AES key)
- Note: The original hash can be sent separately or included in metadata

#### 5. Decryption (Bob)
- **Key Decryption**:
  - Bob loads his RSA private key
  - Decrypts `aes_key_encrypted.bin` to recover the AES key
- **File Decryption**:
  - Extracts IV from the beginning of `encrypted_file.bin`
  - Decrypts the file using AES-256-CBC with the recovered key and IV
  - Saves decrypted content to `decrypted_message.txt`

#### 6. Integrity Verification (Bob)
- Computes SHA-256 hash of the decrypted file
- Compares with the original hash
- If hashes match: File integrity verified ✓
- If hashes differ: File may have been tampered with ✗

## Comparison: AES vs RSA

### AES (Advanced Encryption Standard)

#### Speed
- **Very Fast**: Optimized for hardware and software implementation
- **Efficient**: Can encrypt/decrypt data at high throughput rates
- **Scalable**: Performance scales linearly with data size
- **Example**: Can encrypt gigabytes of data per second on modern hardware

#### Use Case
- **Bulk Data Encryption**: Ideal for encrypting large files or data streams
- **Symmetric Encryption**: Both parties must have the same key
- **Real-time Applications**: Streaming media, database encryption, disk encryption
- **Hybrid Systems**: Used in combination with asymmetric encryption for key exchange

#### Security
- **Key Size**: Supports 128, 192, and 256-bit keys (AES-256 recommended)
- **Security Level**: AES-256 provides 256 bits of security (quantum-resistant)
- **Modes**: Various modes available (CBC, GCM, CTR, etc.)
- **Standard**: NIST-approved standard, widely trusted and analyzed
- **Attack Resistance**: Resistant to known cryptanalytic attacks when properly implemented

### RSA (Rivest-Shamir-Adleman)

#### Speed
- **Slow**: Much slower than symmetric encryption
- **Computational Cost**: Exponentiation operations are expensive
- **Size Limitations**: Can only encrypt data smaller than key size (e.g., 245 bytes for 2048-bit key)
- **Example**: Encrypting 1MB with RSA would require thousands of operations vs. one AES operation

#### Use Case
- **Key Exchange**: Securely sharing symmetric keys
- **Digital Signatures**: Verifying authenticity and non-repudiation
- **Small Data**: Encrypting small amounts of data (like keys or tokens)
- **Public Key Infrastructure**: Foundation of PKI systems
- **Hybrid Systems**: Used to encrypt symmetric keys in hybrid encryption

#### Security
- **Key Size**: Typically 2048-bit (current standard) or 4096-bit (higher security)
- **Security Level**: RSA-2048 provides ~112 bits of security (not quantum-resistant)
- **Mathematical Basis**: Based on difficulty of factoring large numbers
- **Quantum Threat**: Vulnerable to quantum computers (Shor's algorithm)
- **Padding**: Requires proper padding (OAEP recommended) to prevent attacks

### Hybrid Approach: Why Combine Both?

The hybrid encryption approach leverages the strengths of both algorithms:

1. **RSA for Key Exchange**
   - Solves the key distribution problem
   - Allows secure key sharing over insecure channels
   - Only small AES key needs RSA encryption (fast enough)

2. **AES for Data Encryption**
   - Efficient encryption of large files
   - Fast enough for real-time applications
   - Provides strong security with AES-256

3. **SHA-256 for Integrity**
   - Verifies data hasn't been modified
   - Provides tamper detection
   - Fast hash computation

### Performance Comparison Example

For a 10MB file:

| Operation | AES-256 | RSA-2048 |
|-----------|---------|----------|
| Encryption Time | ~0.1 seconds | ~hours (if possible) |
| Key Size | 32 bytes | 256 bytes (public key) |
| Data Size Limit | Unlimited | ~245 bytes per operation |

**Conclusion**: Hybrid encryption provides the best of both worlds - security and efficiency.

## Security Properties

### Confidentiality
- **AES-256**: Provides strong symmetric encryption
- **RSA-2048**: Protects the AES key during transmission
- **Hybrid**: Even if encrypted data is intercepted, decryption requires Bob's private key

### Integrity
- **SHA-256 Hash**: Detects any modifications to the file
- **Verification**: Comparison of hashes confirms file integrity
- **Tamper Detection**: Any change to the file will result in a different hash

### Authentication (Potential Enhancement)
- Current implementation focuses on confidentiality and integrity
- Could be enhanced with digital signatures for sender authentication
- PGP/GPG systems combine encryption with signatures

## File Descriptions

### Input Files
- `alice_message.txt`: Original plaintext file from Alice

### Generated Files
- `public.pem`: Bob's RSA public key (can be shared)
- `private.pem`: Bob's RSA private key (must be kept secret)
- `encrypted_file.bin`: File encrypted with AES-256-CBC (includes IV)
- `aes_key_encrypted.bin`: AES key encrypted with Bob's RSA public key
- `decrypted_message.txt`: Final decrypted file (should match original)

## Usage

1. Ensure Python 3.x and cryptography library are installed:
   ```bash
   pip install cryptography
   ```

2. Run the script:
   ```bash
   python task2_file_exchange.py
   ```

3. The script will:
   - Generate Bob's RSA key pair
   - Encrypt Alice's message
   - Decrypt the message as Bob
   - Verify file integrity

## Security Best Practices

1. **Private Key Protection**: Never share `private.pem` - keep it secure
2. **Random Number Generation**: Uses cryptographically secure random number generator
3. **Key Sizes**: RSA-2048 and AES-256 provide strong security for current standards
4. **IV Uniqueness**: Each encryption uses a new random IV
5. **Padding**: OAEP for RSA and PKCS7 for AES provide security against attacks
6. **Hash Verification**: Always verify file integrity after decryption

## References

- Week 2: Hybrid Encryption Protocols
- Week 4: RSA and AES Implementation
- NIST Special Publication 800-38A (AES modes)
- RFC 3447 (RSA Encryption)

