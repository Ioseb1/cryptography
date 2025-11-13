"""
Task 4A: Simulate Diffie-Hellman Key Exchange
Simulates DH key exchange between Alice and Bob
"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

def generate_dh_parameters():
    """
    Generate Diffie-Hellman parameters (prime p and generator g).
    Uses standard 2048-bit parameters for security.
    """
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def simulate_dh_exchange():
    """
    Simulate Diffie-Hellman key exchange between Alice and Bob.
    """
    print("=" * 60)
    print("Task 4A: Diffie-Hellman Key Exchange Simulation")
    print("=" * 60)
    
    print("\nStep 1: Generating shared DH parameters...")
    parameters = generate_dh_parameters()
    
    parameter_numbers = parameters.parameter_numbers()
    print(f"  Prime p (first 50 chars): {hex(parameter_numbers.p)[:50]}...")
    print(f"  Generator g: {parameter_numbers.g}")
    print(f"  Key size: 2048 bits")
    
    print("\nStep 2: Alice generates her key pair...")
    alice_private_key = parameters.generate_private_key()
    alice_public_key = alice_private_key.public_key()
    
    alice_public_numbers = alice_public_key.public_numbers()
    alice_public_value = alice_public_numbers.y
    
    print(f"  Alice's private key: [SECRET - not shown]")
    print(f"  Alice's public key (y_A): {hex(alice_public_value)[:50]}...")
    print(f"  Alice's public key (full): {hex(alice_public_value)}")
    
    print("\nStep 3: Bob generates his key pair...")
    bob_private_key = parameters.generate_private_key()
    bob_public_key = bob_private_key.public_key()
    
    bob_public_numbers = bob_public_key.public_numbers()
    bob_public_value = bob_public_numbers.y
    
    print(f"  Bob's private key: [SECRET - not shown]")
    print(f"  Bob's public key (y_B): {hex(bob_public_value)[:50]}...")
    print(f"  Bob's public key (full): {hex(bob_public_value)}")
    
    print("\nStep 4: Alice computes shared secret using Bob's public key...")
    alice_shared_secret = alice_private_key.exchange(bob_public_key)
    alice_shared_hex = alice_shared_secret.hex()
    
    print(f"  Shared secret computed by Alice: {alice_shared_hex[:50]}...")
    print(f"  Shared secret (full): {alice_shared_hex}")
    print(f"  Shared secret length: {len(alice_shared_secret)} bytes ({len(alice_shared_secret) * 8} bits)")
    
    print("\nStep 5: Bob computes shared secret using Alice's public key...")
    bob_shared_secret = bob_private_key.exchange(alice_public_key)
    bob_shared_hex = bob_shared_secret.hex()
    
    print(f"  Shared secret computed by Bob: {bob_shared_hex[:50]}...")
    print(f"  Shared secret (full): {bob_shared_hex}")
    print(f"  Shared secret length: {len(bob_shared_secret)} bytes ({len(bob_shared_secret) * 8} bits)")
    
    print("\nStep 6: Verifying shared secrets match...")
    if alice_shared_secret == bob_shared_secret:
        print("  ✓ SUCCESS: Both shared secrets are IDENTICAL!")
        print("  ✓ Alice and Bob have successfully established a shared secret key")
        print("  ✓ This key can now be used for symmetric encryption")
    else:
        print("  ✗ ERROR: Shared secrets do NOT match!")
        print("  This should never happen in a correct DH implementation")
        return False
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print("Alice's Public Key (y_A):")
    print(f"  {hex(alice_public_value)}")
    print("\nBob's Public Key (y_B):")
    print(f"  {hex(bob_public_value)}")
    print("\nShared Secret Key (computed by both):")
    print(f"  {alice_shared_hex}")
    print(f"\n✓ Key exchange successful!")
    print(f"✓ Both parties have the same shared secret")
    print(f"✓ The shared secret can be used for symmetric encryption")
    
    return True

if __name__ == "__main__":
    simulate_dh_exchange()

