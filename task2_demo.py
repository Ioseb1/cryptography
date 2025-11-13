"""
Task 2 Demo: Complete ECC signature generation and verification demonstration
This script demonstrates the full process without requiring interactive input.
"""

from task2_generate_keys import generate_ecc_keys
from task2_sign import sign_message
from task2_verify import verify_signature
import os

def main():
    print("=" * 60)
    print("Task 2A: Generate ECC Keys")
    print("=" * 60)
    
    # Generate ECC key pair
    private_key, public_key = generate_ecc_keys()
    
    print("\n" + "=" * 60)
    print("Task 2B: Sign and Verify Message")
    print("=" * 60)
    
    # Check if ecc.txt exists
    if not os.path.exists("ecc.txt"):
        print("Error: ecc.txt not found!")
        return
    
    # Read and display message
    with open("ecc.txt", 'r') as f:
        message = f.read()
    print(f"\nMessage to sign:")
    print(f"  {message}")
    
    # Sign the message
    print(f"\nSigning ecc.txt...")
    signature = sign_message("ecc.txt", "ecc_private_key.pem", "ecc_signature.bin")
    
    # Verify the signature
    print(f"\nVerifying signature...")
    is_valid = verify_signature("ecc.txt", "ecc_public_key.pem", "ecc_signature.bin")
    
    # Additional verification: try with wrong message (should fail)
    print("\n" + "=" * 60)
    print("Additional Test: Verify with Modified Message")
    print("=" * 60)
    
    # Create a modified message
    with open("ecc_modified.txt", 'w') as f:
        f.write("Elliptic Curves are NOT efficient.")
    
    print(f"\nAttempting to verify modified message...")
    is_valid_modified = verify_signature("ecc_modified.txt", "ecc_public_key.pem", "ecc_signature.bin")
    
    # Clean up
    if os.path.exists("ecc_modified.txt"):
        os.remove("ecc_modified.txt")
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"✓ Keys generated: ecc_private_key.pem, ecc_public_key.pem")
    print(f"✓ Message signed: ecc_signature.bin")
    print(f"✓ Original message verification: {'PASSED' if is_valid else 'FAILED'}")
    print(f"✓ Modified message verification: {'PASSED (unexpected!)' if is_valid_modified else 'FAILED (expected)'}")

if __name__ == "__main__":
    main()

