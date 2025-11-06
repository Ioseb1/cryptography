#!/bin/bash
# OpenSSL Commands for Cryptography Demonstration
# These commands can be used if OpenSSL is installed

# 1. Generate RSA Private Key (2048 bits)
openssl genrsa -out private.pem 2048

# 2. Extract Public Key from Private Key
openssl rsa -in private.pem -pubout -out public.pem

# 3. Encrypt message.txt using RSA Public Key
openssl rsautl -encrypt -pubin -inkey public.pem -in message.txt -out message_rsa_encrypted.bin

# 4. Decrypt RSA Encrypted File
openssl rsautl -decrypt -inkey private.pem -in message_rsa_encrypted.bin -out message_rsa_decrypted.txt

# 5. Generate AES-256 Key (32 bytes = 256 bits)
openssl rand -out aes_key.bin 32

# 6. Generate AES IV (16 bytes = 128 bits)
openssl rand -out aes_iv.bin 16

# 7. Encrypt message.txt using AES-256-CBC
openssl enc -aes-256-cbc -in message.txt -out message_aes_encrypted.bin -K $(xxd -p -c 32 aes_key.bin | tr -d '\n') -iv $(xxd -p -c 16 aes_iv.bin | tr -d '\n')

# Alternative method for AES encryption (using key file):
# openssl enc -aes-256-cbc -in message.txt -out message_aes_encrypted.bin -K $(cat aes_key.bin | xxd -p -c 32) -iv $(cat aes_iv.bin | xxd -p -c 16)

# 8. Decrypt AES Encrypted File
openssl enc -d -aes-256-cbc -in message_aes_encrypted.bin -out message_aes_decrypted.txt -K $(xxd -p -c 32 aes_key.bin | tr -d '\n') -iv $(xxd -p -c 16 aes_iv.bin | tr -d '\n')

