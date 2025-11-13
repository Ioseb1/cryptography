"""
Validation script to test all tasks and verify they work correctly
"""

import os
import sys
import subprocess

def run_script(script_name, description):
    """Run a Python script and return success status"""
    print(f"\n{'='*60}")
    print(f"Testing: {description}")
    print(f"Script: {script_name}")
    print(f"{'='*60}")
    
    if not os.path.exists(script_name):
        print(f"✗ Script not found: {script_name}")
        return False
    
    try:
        result = subprocess.run(
            [sys.executable, script_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"✓ {description} - SUCCESS")
            if result.stdout:
                print("\nOutput:")
                print(result.stdout[:500])
            return True
        else:
            print(f"✗ {description} - FAILED")
            if result.stderr:
                print("\nError:")
                print(result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print(f"✗ {description} - TIMEOUT")
        return False
    except Exception as e:
        print(f"✗ {description} - ERROR: {e}")
        return False

def validate_task1():
    """Validate Task 1: AES Encryption/Decryption"""
    print("\n" + "="*60)
    print("TASK 1: AES Encryption/Decryption")
    print("="*60)
    
    if not os.path.exists("secret.txt"):
        print("✗ secret.txt not found")
        return False
    
    from task1_encrypt import encrypt_file
    from task1_decrypt import decrypt_file
    
    test_passphrase = "TestPass123!"
    
    try:
        encrypt_file("secret.txt", "secret.enc", test_passphrase)
        
        if not os.path.exists("secret.enc"):
            print("✗ Encryption failed - secret.enc not created")
            return False
        
        decrypted_text = decrypt_file("secret.enc", "secret_decrypted.txt", test_passphrase)
        
        with open("secret.txt", 'rb') as f:
            original = f.read()
        
        if decrypted_text == original:
            print("✓ Task 1 validation: SUCCESS")
            return True
        else:
            print("✗ Task 1 validation: Decrypted text doesn't match original")
            return False
    except Exception as e:
        print(f"✗ Task 1 validation failed: {e}")
        return False

def validate_task2():
    """Validate Task 2: ECC Signature"""
    print("\n" + "="*60)
    print("TASK 2: ECC Signature Verification")
    print("="*60)
    
    if not os.path.exists("ecc.txt"):
        print("✗ ecc.txt not found")
        return False
    
    from task2_generate_keys import generate_ecc_keys
    from task2_sign import sign_message
    from task2_verify import verify_signature
    
    try:
        generate_ecc_keys()
        
        if not os.path.exists("ecc_private_key.pem") or not os.path.exists("ecc_public_key.pem"):
            print("✗ Key generation failed")
            return False
        
        sign_message("ecc.txt", "ecc_private_key.pem", "ecc_signature.bin")
        
        if not os.path.exists("ecc_signature.bin"):
            print("✗ Signing failed - signature file not created")
            return False
        
        result = verify_signature("ecc.txt", "ecc_public_key.pem", "ecc_signature.bin")
        
        if result:
            print("✓ Task 2 validation: SUCCESS")
            return True
        else:
            print("✗ Task 2 validation: Signature verification failed")
            return False
    except Exception as e:
        print(f"✗ Task 2 validation failed: {e}")
        return False

def validate_task3():
    """Validate Task 3: Hashing & HMAC"""
    print("\n" + "="*60)
    print("TASK 3: Hashing & HMAC")
    print("="*60)
    
    if not os.path.exists("data.txt"):
        print("✗ data.txt not found")
        return False
    
    from task3a_hash import hash_file_sha256
    from task3b_hmac import compute_hmac_sha256
    from task3c_integrity import compute_hmac_sha256 as compute_hmac, verify_hmac
    
    try:
        hash_value = hash_file_sha256("data.txt")
        if len(hash_value) != 64:
            print("✗ Hash length incorrect (should be 64 hex chars)")
            return False
        
        hmac_value = compute_hmac_sha256("data.txt", "secretkey123")
        if len(hmac_value) != 64:
            print("✗ HMAC length incorrect (should be 64 hex chars)")
            return False
        
        original_hmac = compute_hmac("data.txt", "secretkey123")
        
        with open("data.txt", 'r') as f:
            content = f.read()
        modified_content = content.replace("trust", "trUst")
        
        with open("data_test_modified.txt", 'w') as f:
            f.write(modified_content)
        
        modified_hmac = compute_hmac("data_test_modified.txt", "secretkey123")
        
        if original_hmac == modified_hmac:
            print("✗ HMAC should be different for modified file")
            os.remove("data_test_modified.txt")
            return False
        
        is_valid = verify_hmac("data_test_modified.txt", "secretkey123", original_hmac)
        if is_valid:
            print("✗ Verification should fail for modified file")
            os.remove("data_test_modified.txt")
            return False
        
        os.remove("data_test_modified.txt")
        print("✓ Task 3 validation: SUCCESS")
        return True
    except Exception as e:
        print(f"✗ Task 3 validation failed: {e}")
        if os.path.exists("data_test_modified.txt"):
            os.remove("data_test_modified.txt")
        return False

def validate_task4():
    """Validate Task 4: Diffie-Hellman"""
    print("\n" + "="*60)
    print("TASK 4: Diffie-Hellman Key Exchange")
    print("="*60)
    
    from task4a_dh_exchange import simulate_dh_exchange
    
    try:
        result = simulate_dh_exchange()
        if result:
            print("✓ Task 4 validation: SUCCESS")
            return True
        else:
            print("✗ Task 4 validation: Key exchange failed")
            return False
    except Exception as e:
        print(f"✗ Task 4 validation failed: {e}")
        return False

def main():
    """Run all validations"""
    print("="*60)
    print("VALIDATING ALL TASKS")
    print("="*60)
    
    results = []
    
    results.append(("Task 1: AES", validate_task1()))
    results.append(("Task 2: ECC", validate_task2()))
    results.append(("Task 3: Hash/HMAC", validate_task3()))
    results.append(("Task 4: DH", validate_task4()))
    
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    
    all_passed = True
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{name}: {status}")
        if not result:
            all_passed = False
    
    print("="*60)
    if all_passed:
        print("✓ ALL TASKS VALIDATED SUCCESSFULLY")
    else:
        print("✗ SOME TASKS FAILED VALIDATION")
    print("="*60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())

