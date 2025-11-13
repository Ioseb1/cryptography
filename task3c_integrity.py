"""
Task 3C: Integrity Check
Modifies data.txt, recomputes HMAC, and demonstrates integrity verification
"""

import hmac
import hashlib
import os
import shutil

def compute_hmac_sha256(filename, key):
    """
    Compute HMAC-SHA256 of a file.
    
    Args:
        filename: Path to the file to hash
        key: Secret key (string or bytes)
    
    Returns:
        str: Hexadecimal representation of the HMAC
    """
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key
    
    hmac_obj = hmac.new(key_bytes, digestmod=hashlib.sha256)
    
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hmac_obj.update(byte_block)
    
    return hmac_obj.hexdigest()

def verify_hmac(filename, key, expected_hmac):
    """
    Verify HMAC of a file against expected value.
    
    Args:
        filename: Path to the file to verify
        key: Secret key
        expected_hmac: Expected HMAC value (hex string)
    
    Returns:
        bool: True if HMAC matches, False otherwise
    """
    computed_hmac = compute_hmac_sha256(filename, key)
    return hmac.compare_digest(computed_hmac, expected_hmac)

if __name__ == "__main__":
    filename = "data.txt"
    modified_filename = "data_modified.txt"
    key = "secretkey123"
    
    if not os.path.exists(filename):
        print(f"Error: {filename} not found!")
        exit(1)
    
    print("=" * 60)
    print("Task 3C: Integrity Check")
    print("=" * 60)
    
    with open(filename, 'r') as f:
        original_content = f.read()
    
    print(f"\nStep 1: Original file")
    print(f"  File: {filename}")
    print(f"  Content: {original_content}")
    
    original_hmac = compute_hmac_sha256(filename, key)
    print(f"  Original HMAC-SHA256: {original_hmac}")
    
    modified_content = original_content.replace("trust", "trUst")
    
    with open(modified_filename, 'w') as f:
        f.write(modified_content)
    
    print(f"\nStep 2: Modified file (changed 'trust' to 'trUst')")
    print(f"  File: {modified_filename}")
    print(f"  Content: {modified_content}")
    
    modified_hmac = compute_hmac_sha256(modified_filename, key)
    print(f"  Modified HMAC-SHA256: {modified_hmac}")
    
    print(f"\nStep 3: Comparison")
    print(f"  Original HMAC:  {original_hmac}")
    print(f"  Modified HMAC:  {modified_hmac}")
    
    if original_hmac != modified_hmac:
        print(f"  ✓ HMACs are DIFFERENT - Integrity check FAILED")
        print(f"  ✓ This correctly detects the file modification!")
    else:
        print(f"  ✗ HMACs are the SAME - This should not happen!")
    
    print(f"\nStep 4: Verification using HMAC comparison")
    is_valid = verify_hmac(modified_filename, key, original_hmac)
    print(f"  Verification result: {'VALID' if is_valid else 'INVALID'}")
    print(f"  The modified file does {'NOT ' if not is_valid else ''}match the original HMAC")
    
    print(f"\n" + "=" * 60)
    print("Explanation: Why HMAC is Important")
    print("=" * 60)
    print("""
HMAC (Hash-based Message Authentication Code) is crucial for data integrity 
and authentication because:

1. **Integrity Verification:**
   - Any change to the data, even a single character, produces a completely 
     different HMAC value
   - This allows detection of accidental corruption or malicious tampering

2. **Authentication:**
   - HMAC requires a secret key, so only parties with the key can generate 
     a valid HMAC
   - This ensures the data came from an authorized source

3. **Avalanche Effect:**
   - Changing one letter ('trust' → 'trUst') completely changes the HMAC
   - This demonstrates cryptographic hash properties: small input changes 
     produce large, unpredictable output changes

4. **Security Properties:**
   - Even if an attacker knows the original message and HMAC, they cannot 
     create a valid HMAC for a modified message without the secret key
   - This provides protection against forgery and tampering

5. **Practical Applications:**
   - API authentication (ensuring requests haven't been modified)
   - File integrity checks (detecting corrupted or tampered files)
   - Message authentication in secure communications
   - Digital signatures and verification systems

In this demonstration:
- Original HMAC: {original_hmac}
- Modified HMAC: {modified_hmac}
- The HMACs are different, correctly detecting the modification!
""".format(original_hmac=original_hmac, modified_hmac=modified_hmac))
    
    if os.path.exists(modified_filename):
        print(f"\nNote: Modified file saved as {modified_filename} for reference")
        print(f"      Original file {filename} remains unchanged")

