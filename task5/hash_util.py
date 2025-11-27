#!/usr/bin/env python3
# Task 5: Hashing & Integrity Check Utility

import hashlib
import json
import os
import sys
from datetime import datetime

HASH_FILE = 'hashes.json'

def compute_hashes(file_path):
    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    md5_hash = hashlib.md5()
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
                sha1_hash.update(chunk)
                md5_hash.update(chunk)
        
        return {
            'sha256': sha256_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'md5': md5_hash.hexdigest()
        }
    except FileNotFoundError:
        print(f"ERROR: File '{file_path}' not found.")
        return None
    except Exception as e:
        print(f"ERROR: Failed to compute hashes: {e}")
        return None

def load_hashes():
    if not os.path.exists(HASH_FILE):
        return {}
    
    try:
        with open(HASH_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"WARNING: {HASH_FILE} is corrupted. Starting fresh.")
        return {}
    except Exception as e:
        print(f"ERROR: Failed to load hashes: {e}")
        return {}

def save_hashes(hashes_dict):
    try:
        with open(HASH_FILE, 'w') as f:
            json.dump(hashes_dict, f, indent=2)
        return True
    except Exception as e:
        print(f"ERROR: Failed to save hashes: {e}")
        return False

def compute_and_store(file_path):
    print(f"Computing hashes for: {file_path}")
    print("-" * 60)
    
    hashes = compute_hashes(file_path)
    if hashes is None:
        return False
    
    print(f"SHA-256: {hashes['sha256']}")
    print(f"SHA-1:   {hashes['sha1']}")
    print(f"MD5:     {hashes['md5']}")
    
    stored_hashes = load_hashes()
    
    stored_hashes[file_path] = {
        'sha256': hashes['sha256'],
        'sha1': hashes['sha1'],
        'md5': hashes['md5'],
        'timestamp': datetime.now().isoformat(),
        'file_size': os.path.getsize(file_path)
    }
    
    if save_hashes(stored_hashes):
        print(f"\nHashes stored in {HASH_FILE}")
        return True
    else:
        return False

def verify_integrity(file_path):
    print(f"Verifying integrity of: {file_path}")
    print("=" * 60)
    
    stored_hashes = load_hashes()
    
    if file_path not in stored_hashes:
        print(f"WARNING: No stored hashes found for '{file_path}'")
        print("Run in compute mode first to store hashes.")
        return False
    
    stored = stored_hashes[file_path]
    print(f"Stored timestamp: {stored.get('timestamp', 'Unknown')}")
    print(f"Stored file size: {stored.get('file_size', 'Unknown')} bytes")
    print()
    
    current_hashes = compute_hashes(file_path)
    if current_hashes is None:
        return False
    
    print("Current Hashes:")
    print(f"  SHA-256: {current_hashes['sha256']}")
    print(f"  SHA-1:   {current_hashes['sha1']}")
    print(f"  MD5:     {current_hashes['md5']}")
    print()
    
    print("Stored Hashes:")
    print(f"  SHA-256: {stored['sha256']}")
    print(f"  SHA-1:   {stored['sha1']}")
    print(f"  MD5:     {stored['md5']}")
    print()
    
    print("Comparison Results:")
    print("-" * 60)
    
    sha256_match = current_hashes['sha256'] == stored['sha256']
    sha1_match = current_hashes['sha1'] == stored['sha1']
    md5_match = current_hashes['md5'] == stored['md5']
    
    print(f"SHA-256: {'MATCH' if sha256_match else 'MISMATCH'}")
    print(f"SHA-1:   {'MATCH' if sha1_match else 'MISMATCH'}")
    print(f"MD5:     {'MATCH' if md5_match else 'MISMATCH'}")
    print()
    
    all_match = sha256_match and sha1_match and md5_match
    
    if all_match:
        print("=" * 60)
        print("INTEGRITY CHECK PASSED")
        print("=" * 60)
        print("All hashes match. File integrity verified.")
        return True
    else:
        print("=" * 60)
        print("INTEGRITY CHECK FAILED")
        print("=" * 60)
        print("WARNING: Hash mismatch detected!")
        print("The file may have been tampered with or corrupted.")
        return False

def list_stored_files():
    stored_hashes = load_hashes()
    
    if not stored_hashes:
        print("No stored hashes found.")
        return
    
    print("Files with stored hashes:")
    print("-" * 60)
    for file_path, data in stored_hashes.items():
        print(f"File: {file_path}")
        print(f"  Timestamp: {data.get('timestamp', 'Unknown')}")
        print(f"  File Size: {data.get('file_size', 'Unknown')} bytes")
        print(f"  SHA-256: {data['sha256'][:32]}...")
        print()

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python hash_util.py compute <file_path>  - Compute and store hashes")
        print("  python hash_util.py verify <file_path>   - Verify file integrity")
        print("  python hash_util.py list                 - List stored files")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == 'compute':
        if len(sys.argv) < 3:
            print("ERROR: Please provide a file path.")
            sys.exit(1)
        
        file_path = sys.argv[2]
        success = compute_and_store(file_path)
        sys.exit(0 if success else 1)
    
    elif command == 'verify':
        if len(sys.argv) < 3:
            print("ERROR: Please provide a file path.")
            sys.exit(1)
        
        file_path = sys.argv[2]
        success = verify_integrity(file_path)
        sys.exit(0 if success else 1)
    
    elif command == 'list':
        list_stored_files()
        sys.exit(0)
    
    else:
        print(f"ERROR: Unknown command '{command}'")
        print("Valid commands: compute, verify, list")
        sys.exit(1)

if __name__ == '__main__':
    main()

