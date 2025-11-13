# Task 1: AES Encryption Documentation

## Task 1A: Encrypt a file using AES-128-CBC

### Step 1: Create secret.txt
Created a text file `secret.txt` containing:
```
This file contains top secret information.
```

### Step 2: Encryption Method
Since OpenSSL CLI was not available in the environment, Python with the `cryptography` library was used to implement AES-128-CBC encryption.

**Encryption Implementation:**
- **Algorithm:** AES-128-CBC
- **Key Derivation:** PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Key Size:** 128 bits (16 bytes)
- **Block Size:** 128 bits (16 bytes)
- **Padding:** PKCS7
- **Salt:** 16 random bytes (stored with encrypted file)
- **IV:** 16 random bytes (stored with encrypted file)

### Step 3: Encryption Command/Script
**Python Script:** `task1_encrypt.py`

**Usage:**
```bash
python task1_encrypt.py
```

The script will:
1. Prompt for a passphrase
2. Read `secret.txt`
3. Generate a random salt and IV
4. Derive a 128-bit key from the passphrase using PBKDF2
5. Encrypt the file using AES-128-CBC
6. Save the encrypted file as `secret.enc` (format: salt + IV + ciphertext)

**File Format:**
- Bytes 0-15: Salt (16 bytes)
- Bytes 16-31: IV (16 bytes)
- Bytes 32+: Encrypted ciphertext

### Step 4: Encrypted File
The encrypted file is saved as `secret.enc`.

---

## Task 1B: Decrypt secret.enc

### Step 1: Decryption Method
**Python Script:** `task1_decrypt.py`

**Usage:**
```bash
python task1_decrypt.py
```

The script will:
1. Prompt for the same passphrase used during encryption
2. Read `secret.enc`
3. Extract salt, IV, and ciphertext
4. Derive the same key from the passphrase using PBKDF2
5. Decrypt the file using AES-128-CBC
6. Save the decrypted file as `secret_decrypted.txt`
7. Verify that the decrypted content matches the original

### Step 2: Verification
The decryption script automatically compares the decrypted content with the original `secret.txt` file to verify they match.

---

## Alternative: OpenSSL Commands (if available)

If OpenSSL CLI is available, the following commands can be used:

### Encryption:
```bash
openssl enc -aes-128-cbc -salt -pbkdf2 -in secret.txt -out secret.enc
```
This will prompt for a passphrase.

### Decryption:
```bash
openssl enc -aes-128-cbc -d -salt -pbkdf2 -in secret.enc -out secret_decrypted.txt
```
This will prompt for the same passphrase.

**Note:** The `-pbkdf2` flag uses PBKDF2 for key derivation (OpenSSL 1.1.1+). For older versions, use `-md sha256` instead.

---

## Dependencies

To run the Python scripts, install the cryptography library:
```bash
pip install cryptography
```

Or install from requirements.txt:
```bash
pip install -r requirements.txt
```

## Setup and Execution

### Option 1: Interactive Scripts (Recommended for learning)

1. **Encrypt the file:**
   ```bash
   python task1_encrypt.py
   ```
   Enter a passphrase when prompted.

2. **Decrypt the file:**
   ```bash
   python task1_decrypt.py
   ```
   Enter the same passphrase when prompted.

### Option 2: Demo Script (Automated demonstration)

Run the complete demonstration:
```bash
python task1_demo.py
```

This script will:
- Encrypt `secret.txt` to `secret.enc`
- Decrypt `secret.enc` to `secret_decrypted.txt`
- Verify that the decrypted content matches the original
- Display all results

**Note:** The demo script uses a hardcoded passphrase for demonstration. In production, use the interactive scripts.

---

## Assumptions

1. **Passphrase:** A passphrase is required for encryption/decryption. The user must remember this passphrase to decrypt the file.
2. **Key Derivation:** PBKDF2 with 100,000 iterations is used for key derivation from the passphrase, providing good security against brute-force attacks.
3. **Random Salt and IV:** Each encryption uses a unique salt and IV, ensuring that encrypting the same plaintext twice produces different ciphertexts.
4. **File Format:** The encrypted file stores salt and IV at the beginning, followed by the ciphertext.

---

## Security Notes

- The salt and IV are stored with the encrypted file (not secret, but must be unique)
- The passphrase should be strong and kept secret
- PBKDF2 with 100,000 iterations provides good protection against dictionary attacks
- AES-128-CBC is secure when used correctly (unique IV for each encryption)

