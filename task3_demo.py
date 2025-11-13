"""
Task 3 Demo: Complete hashing and HMAC demonstration
This script demonstrates all three tasks: SHA-256 hash, HMAC, and integrity check
"""

from task3a_hash import hash_file_sha256
from task3b_hmac import compute_hmac_sha256
from task3c_integrity import compute_hmac_sha256, verify_hmac
import os
import shutil

def main():
    filename = "data.txt"
    modified_filename = "data_modified.txt"
    key = "secretkey123"
    
    if not os.path.exists(filename):
        print(f"Error: {filename} not found!")
        return
    
    # Task 3A: SHA-256 Hash
    print("=" * 60)
    print("Task 3A: SHA-256 Hash")
    print("=" * 60)
    
    with open(filename, 'r') as f:
        content = f.read()
    
    print(f"\nFile: {filename}")
    print(f"Content: {content}")
    
    hash_value = hash_file_sha256(filename)
    print(f"\nSHA-256 Hash: {hash_value}")
    
    # Task 3B: HMAC
    print("\n" + "=" * 60)
    print("Task 3B: HMAC using SHA-256")
    print("=" * 60)
    
    print(f"\nFile: {filename}")
    print(f"Content: {content}")
    print(f"Key: {key}")
    
    hmac_value = compute_hmac_sha256(filename, key)
    print(f"\nHMAC-SHA256: {hmac_value}")
    
    # Task 3C: Integrity Check
    print("\n" + "=" * 60)
    print("Task 3C: Integrity Check")
    print("=" * 60)
    
    # Store original HMAC
    original_hmac = hmac_value
    
    # Modify the file (change one letter)
    modified_content = content.replace("trust", "trUst")
    
    # Save modified version
    with open(modified_filename, 'w') as f:
        f.write(modified_content)
    
    print(f"\nOriginal content: {content}")
    print(f"Modified content: {modified_content}")
    print(f"  (Changed 'trust' to 'trUst')")
    
    # Recompute HMAC for modified file
    modified_hmac = compute_hmac_sha256(modified_filename, key)
    
    print(f"\nOriginal HMAC:  {original_hmac}")
    print(f"Modified HMAC:  {modified_hmac}")
    
    # Verify
    is_valid = verify_hmac(modified_filename, key, original_hmac)
    
    print(f"\nVerification: {'PASSED' if is_valid else 'FAILED'}")
    if not is_valid:
        print("✓ Correctly detected file modification!")
    
    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"✓ SHA-256 Hash computed: {hash_value}")
    print(f"✓ HMAC-SHA256 computed: {hmac_value}")
    print(f"✓ Integrity check: Modification detected (HMAC changed)")
    print(f"\nFiles created:")
    print(f"  - {filename} (original)")
    print(f"  - {modified_filename} (modified for testing)")

if __name__ == "__main__":
    main()

