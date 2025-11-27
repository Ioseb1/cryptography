# Hashing & Integrity Check Utility

## Overview
This utility computes SHA-256, SHA-1, and MD5 hashes of files and provides integrity verification to detect tampering or corruption.

## Features
- Computes three hash algorithms: SHA-256, SHA-1, and MD5
- Stores hashes in JSON format with metadata (timestamp, file size)
- Verifies file integrity by comparing current hashes with stored hashes
- Detects tampering and corruption
- Lists all files with stored hashes

## Usage

### Compute and Store Hashes
```bash
python hash_util.py compute <file_path>
```

Example:
```bash
python hash_util.py compute original.txt
```

This will:
- Compute SHA-256, SHA-1, and MD5 hashes
- Display the computed hashes
- Store them in `hashes.json` with metadata

### Verify File Integrity
```bash
python hash_util.py verify <file_path>
```

Example:
```bash
python hash_util.py verify original.txt
python hash_util.py verify tampered.txt
```

This will:
- Load stored hashes from `hashes.json`
- Compute current hashes of the file
- Compare current hashes with stored hashes
- Display pass/fail result

### List Stored Files
```bash
python hash_util.py list
```

This displays all files that have stored hashes.

## Demonstration

### Step 1: Compute Hashes of Original File
```bash
python hash_util.py compute original.txt
```

Output:
```
Computing hashes for: original.txt
------------------------------------------------------------
SHA-256: abc123def456...
SHA-1:   xyz789uvw012...
MD5:     qwe345rty678...

Hashes stored in hashes.json
```

### Step 2: Verify Original File (Should Pass)
```bash
python hash_util.py verify original.txt
```

Output:
```
Verifying integrity of: original.txt
============================================================
Stored timestamp: 2025-11-27T17:20:00.123456
Stored file size: 512 bytes

Current Hashes:
  SHA-256: abc123def456...
  SHA-1:   xyz789uvw012...
  MD5:     qwe345rty678...

Stored Hashes:
  SHA-256: abc123def456...
  SHA-1:   xyz789uvw012...
  MD5:     qwe345rty678...

Comparison Results:
------------------------------------------------------------
SHA-256: ✓ MATCH
SHA-1:   ✓ MATCH
MD5:     ✓ MATCH

============================================================
✓ INTEGRITY CHECK PASSED
============================================================
All hashes match. File integrity verified.
The file has not been tampered with.
```

### Step 3: Verify Tampered File (Should Fail)
```bash
python hash_util.py verify tampered.txt
```

Output:
```
Verifying integrity of: tampered.txt
============================================================
Stored timestamp: 2025-11-27T17:20:00.123456
Stored file size: 512 bytes

Current Hashes:
  SHA-256: def456ghi789...  (different!)
  SHA-1:   uvw012xyz345...  (different!)
  MD5:     rty678iop901...  (different!)

Stored Hashes:
  SHA-256: abc123def456...
  SHA-1:   xyz789uvw012...
  MD5:     qwe345rty678...

Comparison Results:
------------------------------------------------------------
SHA-256: ✗ MISMATCH
SHA-1:   ✗ MISMATCH
MD5:     ✗ MISMATCH

============================================================
✗ INTEGRITY CHECK FAILED
============================================================
WARNING: Hash mismatch detected!
The file may have been tampered with or corrupted.

Possible causes:
  - File was modified
  - File was corrupted
  - File was replaced with a different file
```

## Hash Algorithms Explained

### SHA-256 (Secure Hash Algorithm 256-bit)
- **Output**: 256 bits (64 hexadecimal characters)
- **Security**: Strong, recommended for most applications
- **Use Case**: Modern standard for file integrity
- **Status**: Current standard, widely used

### SHA-1 (Secure Hash Algorithm 1)
- **Output**: 160 bits (40 hexadecimal characters)
- **Security**: Deprecated, vulnerable to collision attacks
- **Use Case**: Legacy systems, not recommended for new applications
- **Status**: Deprecated but still computed for compatibility

### MD5 (Message Digest 5)
- **Output**: 128 bits (32 hexadecimal characters)
- **Security**: Broken, vulnerable to collision attacks
- **Use Case**: Legacy systems, checksums (not security)
- **Status**: Cryptographically broken, use only for non-security purposes

## JSON Storage Format

The `hashes.json` file stores hashes in the following format:

```json
{
  "original.txt": {
    "sha256": "abc123def456...",
    "sha1": "xyz789uvw012...",
    "md5": "qwe345rty678...",
    "timestamp": "2025-11-27T17:20:00.123456",
    "file_size": 512
  },
  "another_file.txt": {
    "sha256": "...",
    "sha1": "...",
    "md5": "...",
    "timestamp": "...",
    "file_size": 1024
  }
}
```

## How Integrity Checking Works

1. **Initial Hash Computation**:
   - File is read and hashed using SHA-256, SHA-1, and MD5
   - Hashes are stored in `hashes.json` with metadata

2. **Integrity Verification**:
   - Current file is hashed again using the same algorithms
   - Current hashes are compared with stored hashes
   - If all hashes match: File integrity verified ✓
   - If any hash differs: Tampering detected ✗

3. **Tamper Detection**:
   - Any change to the file (even a single byte) produces different hashes
   - Hash functions are designed to be:
     - **Deterministic**: Same input always produces same output
     - **Avalanche Effect**: Small change produces completely different hash
     - **One-way**: Cannot derive original file from hash

## Security Considerations

### Hash Algorithm Selection
- **SHA-256**: Use for security-critical applications
- **SHA-1**: Avoid for new applications (deprecated)
- **MD5**: Avoid for security purposes (broken)

### Best Practices
1. Use SHA-256 for primary integrity checks
2. Store hashes securely (separate from files being checked)
3. Verify hashes regularly for critical files
4. Use multiple hash algorithms for redundancy
5. Keep backup copies of hash files

## Limitations

1. **Hash Collisions**: Theoretically possible but practically infeasible for SHA-256
2. **File Replacement**: Cannot detect if file was replaced with different file of same hash (extremely unlikely)
3. **Metadata Changes**: May not detect changes to file metadata (permissions, timestamps) if file content is unchanged
4. **Hash Storage**: If `hashes.json` is compromised, integrity checks become unreliable

## Use Cases

- **File Integrity Monitoring**: Detect unauthorized modifications
- **Backup Verification**: Ensure backups are not corrupted
- **Software Distribution**: Verify downloaded software hasn't been tampered with
- **Forensic Analysis**: Detect changes to files over time
- **Compliance**: Meet requirements for data integrity verification

## Files

- `hash_util.py`: Main Python script
- `original.txt`: Original file for testing
- `tampered.txt`: Modified version to demonstrate tamper detection
- `hashes.json`: JSON file storing computed hashes (generated when running script)

## Requirements

- Python 3.x
- Standard library only (no external dependencies)

## Example Workflow

```bash
# 1. Compute hashes of original file
python hash_util.py compute original.txt

# 2. Verify original file (should pass)
python hash_util.py verify original.txt

# 3. Modify the file (or use tampered.txt)
# ... file is modified ...

# 4. Verify modified file (should fail)
python hash_util.py verify original.txt

# 5. List all stored files
python hash_util.py list
```

