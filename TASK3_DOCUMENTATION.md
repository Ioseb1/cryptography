# Task 3: Hashing & HMAC Documentation

## Task 3A: SHA-256 Hash

### Step 1: Create data.txt
Created a text file `data.txt` containing:
```
Never trust, always verify.
```

### Step 2: Hash the File
**Python Script:** `task3a_hash.py`

**Usage:**
```bash
python task3a_hash.py
```

The script computes the SHA-256 hash of `data.txt`.

**Hash Output:**
The script will display the SHA-256 hash in hexadecimal format. Example output:
```
SHA-256 Hash: [64-character hexadecimal string]
```

**SHA-256 Details:**
- **Algorithm:** SHA-256 (Secure Hash Algorithm 256-bit)
- **Output Size:** 256 bits (32 bytes)
- **Output Format:** Hexadecimal string (64 characters)
- **Properties:**
  - Deterministic: Same input always produces same output
  - One-way: Cannot reverse to get original input
  - Avalanche effect: Small input changes produce large output changes
  - Collision resistant: Hard to find two inputs with same hash

### Alternative: CLI Commands

**Using Python CLI:**
```bash
python -c "import hashlib; print(hashlib.sha256(open('data.txt', 'rb').read()).hexdigest())"
```

**Using OpenSSL (if available):**
```bash
openssl dgst -sha256 data.txt
```

**Using PowerShell (Windows):**
```powershell
Get-FileHash -Path data.txt -Algorithm SHA256
```

---

## Task 3B: HMAC using SHA-256

### Step 1: HMAC Creation
**Python Script:** `task3b_hmac.py`

**Usage:**
```bash
python task3b_hmac.py
```

The script creates an HMAC for `data.txt` using:
- **Key:** `secretkey123`
- **Hash Algorithm:** SHA-256
- **Result:** HMAC-SHA256

**HMAC Output:**
The script will display the HMAC-SHA256 value in hexadecimal format.

**HMAC Details:**
- **Full Name:** HMAC-SHA256 (Hash-based Message Authentication Code using SHA-256)
- **Output Size:** 256 bits (32 bytes)
- **Output Format:** Hexadecimal string (64 characters)
- **Key:** `secretkey123` (as specified)

### HMAC vs Hash

**SHA-256 Hash:**
- Only requires the data
- Anyone can compute the hash
- No authentication

**HMAC-SHA256:**
- Requires both data and secret key
- Only parties with the key can generate valid HMAC
- Provides both integrity and authentication

### Alternative: CLI Commands

**Using Python CLI:**
```bash
python -c "import hmac, hashlib; print(hmac.new(b'secretkey123', open('data.txt', 'rb').read(), hashlib.sha256).hexdigest())"
```

**Using OpenSSL (if available):**
```bash
openssl dgst -sha256 -hmac secretkey123 data.txt
```

---

## Task 3C: Integrity Check

### Step 1: Modify data.txt
**Python Script:** `task3c_integrity.py`

**Usage:**
```bash
python task3c_integrity.py
```

The script:
1. Computes the original HMAC for `data.txt`
2. Creates a modified version (changes one letter: "trust" → "trUst")
3. Computes the HMAC for the modified file
4. Compares the two HMACs
5. Explains why HMAC is important

### Step 2: Results

**What Happens:**
- The original HMAC and modified HMAC are **completely different**
- Even though only one letter was changed, the entire HMAC value changed
- This demonstrates the **avalanche effect** of cryptographic hash functions

**Example Output:**
```
Original HMAC:  [64-character hex string]
Modified HMAC:  [completely different 64-character hex string]
Verification: FAILED
✓ Correctly detected file modification!
```

### Step 3: Explanation - Why HMAC is Important

#### 1. **Data Integrity Verification**
- HMAC detects any changes to the data, no matter how small
- Even changing a single character produces a completely different HMAC
- This allows verification that data has not been corrupted or tampered with

#### 2. **Authentication**
- HMAC requires a secret key to generate
- Only parties with the correct key can produce a valid HMAC
- This ensures the data came from an authorized source

#### 3. **Avalanche Effect**
- Small changes in input produce large, unpredictable changes in output
- Changing "trust" to "trUst" (one character) completely changes the HMAC
- This makes it impossible to predict how modifications will affect the HMAC

#### 4. **Security Properties**
- **Non-repudiation:** The sender cannot deny creating the HMAC (if key is secret)
- **Tamper Detection:** Any modification invalidates the HMAC
- **Key Dependency:** Without the secret key, an attacker cannot create a valid HMAC for modified data

#### 5. **Practical Applications**
- **API Security:** Verify that API requests haven't been modified
- **File Integrity:** Check if files have been corrupted or tampered with
- **Message Authentication:** Ensure messages in secure communications are authentic
- **Digital Signatures:** Foundation for many digital signature schemes
- **Software Distribution:** Verify downloaded software hasn't been modified

#### 6. **Comparison: Hash vs HMAC**

| Feature | SHA-256 Hash | HMAC-SHA256 |
|---------|--------------|-------------|
| Requires key | No | Yes |
| Authentication | No | Yes |
| Integrity check | Yes | Yes |
| Tamper detection | Yes | Yes |
| Source verification | No | Yes |
| Resistant to forgery | No (anyone can compute) | Yes (requires key) |

### Demonstration Results

In this task:
1. **Original file:** "Never trust, always verify."
2. **Original HMAC:** Computed with key "secretkey123"
3. **Modified file:** "Never trUst, always verify." (changed 't' to 'U')
4. **Modified HMAC:** Completely different from original
5. **Verification:** FAILED - correctly detects modification

This demonstrates that:
- HMAC is sensitive to even the smallest changes
- Without the secret key, an attacker cannot create a valid HMAC for modified data
- HMAC provides both integrity and authentication guarantees

---

## Complete Demo

**Python Script:** `task3_demo.py`

Run the complete demonstration:
```bash
python task3_demo.py
```

This script will:
1. Compute SHA-256 hash of `data.txt`
2. Compute HMAC-SHA256 of `data.txt` with key "secretkey123"
3. Modify the file and recompute HMAC
4. Show that the HMACs are different
5. Display summary of all operations

---

## Dependencies

The Python scripts use the built-in `hashlib` and `hmac` libraries (no external dependencies required):
- `hashlib` - For SHA-256 hashing
- `hmac` - For HMAC computation

These are part of Python's standard library, so no installation is needed.

---

## File Structure

After running all scripts, you should have:
```
.
├── data.txt                    # Original message
├── data_modified.txt           # Modified version (for Task 3C)
├── task3a_hash.py             # SHA-256 hash script
├── task3b_hmac.py              # HMAC script
├── task3c_integrity.py         # Integrity check script
└── task3_demo.py               # Complete demo script
```

---

## Code/Command Summary

### Task 3A: SHA-256 Hash

**Python Code:**
```python
import hashlib

def hash_file_sha256(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

hash_value = hash_file_sha256("data.txt")
print(hash_value)
```

**CLI Command:**
```bash
python -c "import hashlib; print(hashlib.sha256(open('data.txt', 'rb').read()).hexdigest())"
```

### Task 3B: HMAC-SHA256

**Python Code:**
```python
import hmac
import hashlib

key = "secretkey123"
hmac_obj = hmac.new(key.encode('utf-8'), digestmod=hashlib.sha256)
with open("data.txt", "rb") as f:
    hmac_obj.update(f.read())
hmac_value = hmac_obj.hexdigest()
print(hmac_value)
```

**CLI Command:**
```bash
python -c "import hmac, hashlib; print(hmac.new(b'secretkey123', open('data.txt', 'rb').read(), hashlib.sha256).hexdigest())"
```

### Task 3C: Integrity Check

**Process:**
1. Compute original HMAC
2. Modify file (change one character)
3. Compute new HMAC
4. Compare: HMACs are different → modification detected

**Key Insight:**
Even a single character change produces a completely different HMAC, demonstrating the avalanche effect and the importance of HMAC for integrity verification.

---

## Assumptions

1. **Key:** The key "secretkey123" is used as specified (in production, use stronger keys)
2. **File Encoding:** Files are read in binary mode for consistent hashing
3. **Modification:** One letter is changed ("trust" → "trUst") to demonstrate integrity check
4. **Hash Algorithm:** SHA-256 is used throughout (standard and secure)

---

## Security Notes

- **Key Security:** In production, keep the HMAC key secret and secure
- **Key Strength:** Use strong, randomly generated keys (not simple strings like "secretkey123")
- **Key Management:** Store keys securely (key management systems, environment variables, etc.)
- **Constant-Time Comparison:** The scripts use `hmac.compare_digest()` for secure comparison (prevents timing attacks)

