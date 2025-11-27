# Encryption Flow Explanation

## Overview
This document explains the hybrid encryption flow used in the Encrypted Messaging App Prototype. The system combines RSA (asymmetric encryption) and AES (symmetric encryption) to achieve both security and efficiency.

## Encryption Flow Diagram

```
User A                          User B
  |                               |
  |--[1] Generate RSA Key Pair----|
  |                               |
  |--[2] Share Public Key-------->|
  |                               |
  |                               |--[3] Generate AES-256 Key
  |                               |--[4] Encrypt Message (AES)
  |                               |--[5] Encrypt AES Key (RSA)
  |                               |
  |<--[6] Receive Encrypted Data--|
  |                               |
  |--[7] Decrypt AES Key (RSA)---|
  |--[8] Decrypt Message (AES)---|
  |                               |
```

## Step-by-Step Process

### Step 1: Key Generation (User A)
- User A generates an RSA key pair (2048-bit)
- The key pair consists of:
  - **Private Key**: Kept secret by User A, used for decryption
  - **Public Key**: Shared with User B, used for encryption
- Keys are saved in PEM format:
  - `private_key.pem` - User A's private key (must be kept secret)
  - `public_key.pem` - User A's public key (can be shared)

### Step 2: Key Sharing
- User A shares `public_key.pem` with User B
- The public key can be shared over insecure channels
- Anyone can encrypt data with the public key, but only User A can decrypt it

### Step 3: Message Encryption (User B)

#### 3.1 AES Key Generation
- User B generates a random 256-bit (32-byte) AES key
- This key is used for symmetric encryption of the actual message
- AES is chosen because it's much faster than RSA for large data

#### 3.2 AES Encryption
- User B reads the plaintext message from `message.txt`
- Generates a random Initialization Vector (IV) - 16 bytes for AES-CBC
- Encrypts the message using AES-256-CBC mode:
  - The message is padded to align with AES block size (16 bytes)
  - CBC (Cipher Block Chaining) mode provides security against pattern analysis
- The IV is prepended to the encrypted message for later decryption
- Saves encrypted data to `encrypted_message.bin`

#### 3.3 RSA Encryption of AES Key
- User B encrypts the AES key using User A's RSA public key
- Uses OAEP (Optimal Asymmetric Encryption Padding) with SHA-256
- OAEP provides security against certain attacks (e.g., chosen ciphertext attacks)
- Saves encrypted AES key to `aes_key_encrypted.bin`

### Step 4: Message Decryption (User A)

#### 4.1 RSA Decryption
- User A loads their private key from `private_key.pem`
- Decrypts the AES key from `aes_key_encrypted.bin` using RSA private key
- This recovers the original AES-256 key

#### 4.2 AES Decryption
- User A extracts the IV from the beginning of `encrypted_message.bin` (first 16 bytes)
- Uses the decrypted AES key and IV to decrypt the message
- Removes padding to recover the original plaintext
- Saves decrypted message to `decrypted_message.txt`

## Why Hybrid Encryption?

### Advantages of RSA
- **Asymmetric**: Public key can be shared freely
- **Key Exchange**: Solves the key distribution problem
- **Digital Signatures**: Can also be used for authentication

### Disadvantages of RSA
- **Slow**: Much slower than symmetric encryption
- **Size Limitations**: Can only encrypt small amounts of data (depends on key size)
- **Computational Cost**: Expensive for large files

### Advantages of AES
- **Fast**: Very efficient for bulk data encryption
- **Secure**: Industry-standard symmetric encryption
- **Scalable**: Can encrypt data of any size

### Disadvantages of AES
- **Symmetric**: Same key used for encryption and decryption
- **Key Distribution**: Requires secure channel to share the key

### Hybrid Approach Benefits
1. **Best of Both Worlds**: Combines RSA's key exchange capability with AES's speed
2. **Efficiency**: Only small AES key is encrypted with RSA, not the entire message
3. **Security**: Maintains security properties of both algorithms
4. **Scalability**: Can handle messages of any size efficiently

## Security Properties

### Confidentiality
- The message is encrypted with AES-256, providing strong confidentiality
- The AES key is protected by RSA-2048 encryption
- Even if encrypted data is intercepted, it cannot be decrypted without User A's private key

### Integrity
- While this implementation focuses on confidentiality, integrity can be added using:
  - HMAC (Hash-based Message Authentication Code)
  - Digital signatures
  - Authenticated encryption modes (e.g., AES-GCM)

### Forward Secrecy
- Each message uses a new random AES key
- Compromising one message doesn't affect others
- However, if RSA private key is compromised, all past messages can be decrypted

## File Descriptions

- `message.txt`: Original plaintext message
- `public_key.pem`: User A's RSA public key (can be shared)
- `private_key.pem`: User A's RSA private key (must be kept secret)
- `encrypted_message.bin`: Message encrypted with AES-256-CBC
- `aes_key_encrypted.bin`: AES key encrypted with RSA public key
- `decrypted_message.txt`: Final decrypted message (should match original)

## Usage

1. Run `python task1_messaging.py`
2. The script will:
   - Generate RSA keys
   - Encrypt the message (User B simulation)
   - Decrypt the message (User A simulation)
   - Verify that decryption matches the original

## Security Considerations

1. **Private Key Protection**: The private key must be kept secure and never shared
2. **Random Number Generation**: Uses `os.urandom()` for cryptographically secure random numbers
3. **Key Size**: RSA-2048 and AES-256 provide strong security for current standards
4. **Padding**: OAEP padding for RSA and PKCS7 padding for AES provide security against attacks
5. **IV Reuse**: Each encryption uses a new random IV to prevent pattern analysis

