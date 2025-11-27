#!/usr/bin/env python3
# Task 3: TLS Communication Inspection & Analysis

import subprocess
import re
import sys

def run_openssl_s_client(hostname='google.com', port=443):
    print(f"Connecting to {hostname}:{port}...")
    print("=" * 60)
    
    try:
        result = subprocess.run(
            ['openssl', 's_client', '-connect', f'{hostname}:{port}', '-showcerts'],
            input=b'',
            capture_output=True,
            text=True,
            timeout=10
        )
        
        output = result.stdout + result.stderr
        return output
    except FileNotFoundError:
        print("ERROR: openssl not found. Please install OpenSSL.")
        return None
    except subprocess.TimeoutExpired:
        print("ERROR: Connection timeout.")
        return None
    except Exception as e:
        print(f"ERROR: {e}")
        return None

def extract_certificate_chain(output):
    print("\n=== Certificate Chain ===")
    
    cert_pattern = r'-----BEGIN CERTIFICATE-----\n(.*?)\n-----END CERTIFICATE-----'
    certificates = re.findall(cert_pattern, output, re.DOTALL)
    
    if certificates:
        print(f"Found {len(certificates)} certificate(s) in chain:")
        for i, cert in enumerate(certificates, 1):
            print(f"\nCertificate {i}:")
            print(f"  Length: {len(cert)} characters")
            cert_start = output.find(f"Certificate {i}")
            if cert_start != -1:
                cert_section = output[cert_start:cert_start+500]
                subject_match = re.search(r'Subject: (.+)', cert_section)
                issuer_match = re.search(r'Issuer: (.+)', cert_section)
                if subject_match:
                    print(f"  Subject: {subject_match.group(1)}")
                if issuer_match:
                    print(f"  Issuer: {issuer_match.group(1)}")
    else:
        print("No certificates found in output")
    
    return certificates

def extract_cipher_suite(output):
    print("\n=== Cipher Suite ===")
    
    cipher_match = re.search(r'Cipher\s*:\s*(.+)', output)
    if cipher_match:
        cipher = cipher_match.group(1).strip()
        print(f"Cipher: {cipher}")
        
        cipher_details_match = re.search(r'Cipher is (.+)', output)
        if cipher_details_match:
            print(f"Details: {cipher_details_match.group(1)}")
        
        return cipher
    else:
        print("Cipher suite not found")
        return None

def extract_tls_version(output):
    print("\n=== TLS Version ===")
    
    protocol_match = re.search(r'Protocol\s*:\s*(.+)', output)
    if protocol_match:
        protocol = protocol_match.group(1).strip()
        print(f"Protocol: {protocol}")
        return protocol
    else:
        print("TLS version not found")
        return None

def extract_certificate_info(output):
    print("\n=== Certificate Details ===")
    
    subject_match = re.search(r'Subject:\s*(.+)', output)
    if subject_match:
        print(f"Subject: {subject_match.group(1)}")
    
    issuer_match = re.search(r'Issuer:\s*(.+)', output)
    if issuer_match:
        print(f"Issuer: {issuer_match.group(1)}")
    
    not_before_match = re.search(r'Not Before\s*:\s*(.+)', output)
    if not_before_match:
        print(f"Valid From: {not_before_match.group(1)}")
    
    not_after_match = re.search(r'Not After\s*:\s*(.+)', output)
    if not_after_match:
        print(f"Valid Until: {not_after_match.group(1)}")

def main():
    hostname = sys.argv[1] if len(sys.argv) > 1 else 'google.com'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    print("=" * 60)
    print("TLS Communication Inspection & Analysis")
    print("=" * 60)
    
    output = run_openssl_s_client(hostname, port)
    
    if output is None:
        print("\nFailed to connect. Please check:")
        print("1. OpenSSL is installed")
        print("2. Internet connection is available")
        print("3. Hostname and port are correct")
        return
    
    with open('tls_output.txt', 'w') as f:
        f.write(output)
    print("\nRaw output saved to tls_output.txt")
    
    certificates = extract_certificate_chain(output)
    cipher = extract_cipher_suite(output)
    protocol = extract_tls_version(output)
    extract_certificate_info(output)
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Hostname: {hostname}")
    print(f"Port: {port}")
    print(f"TLS Version: {protocol if protocol else 'Not found'}")
    print(f"Cipher Suite: {cipher if cipher else 'Not found'}")
    print(f"Certificates in Chain: {len(certificates) if certificates else 0}")
    print("=" * 60)
    
    print("\nNote: For detailed Wireshark analysis, please refer to task3_instructions.md")

if __name__ == '__main__':
    main()

