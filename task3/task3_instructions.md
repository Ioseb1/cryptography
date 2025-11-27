# Wireshark TLS Handshake Capture Instructions

## Overview
This guide explains how to capture and analyze a TLS handshake using Wireshark, focusing on the key components: Client Hello, Server Certificate, and Key Exchange.

## Prerequisites
- Wireshark installed on your system
- Administrator/root privileges (required for packet capture)
- Basic understanding of network protocols

## Step-by-Step Instructions

### Step 1: Prepare Wireshark

1. **Launch Wireshark** with administrator/root privileges
2. **Select Network Interface**:
   - Choose the active network interface (e.g., Wi-Fi adapter, Ethernet adapter)
   - Look for interfaces showing traffic activity (packets moving)

### Step 2: Set Capture Filter (Optional)

Before starting capture, you can set a filter to capture only HTTPS traffic:
```
tcp port 443
```

This filters packets to only show traffic on port 443 (HTTPS).

### Step 3: Start Packet Capture

1. Click the **"Start capturing packets"** button (blue shark fin icon)
2. Open a web browser
3. Navigate to an HTTPS website (e.g., https://www.google.com)
4. Wait for the page to load completely
5. **Stop the capture** (red square button)

### Step 4: Filter TLS Traffic

In the filter bar at the top, enter:
```
tls
```

This will show only TLS/SSL packets. You should see packets labeled as:
- Client Hello
- Server Hello
- Certificate
- Server Key Exchange
- Client Key Exchange
- etc.

### Step 5: Analyze TLS Handshake

#### 5.1 Client Hello
1. **Find the Client Hello packet**:
   - Look for a packet with "Client Hello" in the Info column
   - Usually the first TLS packet in the connection

2. **Examine Client Hello details**:
   - Right-click the packet → **Follow → TLS Stream**
   - Or expand the packet tree: **Transport Layer Security → TLSv1.2 Record Layer → Handshake Protocol: Client Hello**

3. **Key information to note**:
   - **TLS Version**: What TLS version the client supports (e.g., TLS 1.2, TLS 1.3)
   - **Cipher Suites**: List of cipher suites the client supports
   - **Random**: Client random value (32 bytes)
   - **Session ID**: Session identifier (if resuming a session)
   - **Extensions**: Supported extensions (SNI, supported groups, etc.)

#### 5.2 Server Certificate
1. **Find the Certificate packet**:
   - Look for a packet with "Certificate" in the Info column
   - Usually sent by the server after Server Hello

2. **Examine Certificate details**:
   - Expand: **Transport Layer Security → TLSv1.2 Record Layer → Handshake Protocol: Certificate**
   - You'll see the certificate chain

3. **Key information to note**:
   - **Certificate Chain**: Multiple certificates (Root CA → Intermediate CA → Server Certificate)
   - **Subject**: Who the certificate is issued to (e.g., CN=www.google.com)
   - **Issuer**: Who issued the certificate (Certificate Authority)
   - **Validity Period**: When the certificate is valid
   - **Public Key**: Server's public key (RSA or ECC)

#### 5.3 Key Exchange
1. **Find Key Exchange packets**:
   - **Server Key Exchange** (if present): Contains server's key exchange parameters
   - **Client Key Exchange**: Contains client's encrypted pre-master secret

2. **Examine Key Exchange details**:
   - Expand: **Transport Layer Security → Handshake Protocol: Client Key Exchange**
   - For RSA: Shows encrypted pre-master secret
   - For ECDHE: Shows server's ephemeral public key and client's ephemeral public key

3. **Key information to note**:
   - **Key Exchange Algorithm**: RSA, ECDHE, DHE, etc.
   - **Pre-master Secret**: Encrypted random value (for RSA) or computed shared secret (for ECDHE)
   - **Random Values**: Client and server random values used in key derivation

### Step 6: Export and Document

1. **Take Screenshots**:
   - Screenshot of the packet list showing TLS handshake packets
   - Screenshot of Client Hello details
   - Screenshot of Server Certificate details
   - Screenshot of Key Exchange details

2. **Save Capture File**:
   - File → Save As → Save as `tls_handshake.pcapng`

3. **Export TLS Stream**:
   - Right-click on a TLS packet → Follow → TLS Stream
   - Save the stream text for analysis

## What to Look For

### Client Hello Highlights
- **Supported TLS versions**: Check what versions the client offers
- **Cipher suite list**: Ordered list of preferred cipher suites
- **Server Name Indication (SNI)**: The hostname the client wants to connect to
- **Supported groups**: For ECDHE/DHE key exchange

### Server Certificate Highlights
- **Certificate chain**: Root CA → Intermediate CA → Leaf Certificate
- **Certificate validity**: Check expiration dates
- **Subject Alternative Names (SAN)**: Additional domains covered by the certificate
- **Public key algorithm**: RSA or ECC (Elliptic Curve Cryptography)

### Key Exchange Highlights
- **Key exchange method**: RSA, ECDHE, DHE, etc.
- **Forward secrecy**: ECDHE/DHE provide forward secrecy (RSA does not)
- **Key size**: Length of the keys used (e.g., RSA-2048, ECDHE P-256)

## Common TLS Handshake Flow

```
Client                          Server
  |                               |
  |--[1] Client Hello------------->|
  |   (TLS version, cipher suites) |
  |                               |
  |<--[2] Server Hello------------|
  |   (Selected TLS version,      |
  |    selected cipher suite)     |
  |                               |
  |<--[3] Certificate-------------|
  |   (Server certificate chain)  |
  |                               |
  |<--[4] Server Key Exchange----|
  |   (If ECDHE/DHE)              |
  |                               |
  |<--[5] Server Hello Done------|
  |                               |
  |--[6] Client Key Exchange----->|
  |   (Encrypted pre-master       |
  |    secret or ephemeral key)   |
  |                               |
  |--[7] Change Cipher Spec------>|
  |   (Switch to encrypted mode)  |
  |                               |
  |--[8] Finished---------------->|
  |   (Encrypted handshake        |
  |    verification)               |
  |                               |
  |<--[9] Change Cipher Spec-----|
  |                               |
  |<--[10] Finished---------------|
  |                               |
  |<==== Encrypted Data =========>|
```

## Troubleshooting

### No TLS Packets Visible
- Ensure you're capturing on the correct network interface
- Check that the website uses HTTPS (port 443)
- Verify the TLS filter is applied correctly

### Can't See Certificate Details
- Make sure you're expanding the packet tree fully
- Try right-clicking → "Follow TLS Stream" for a different view
- Check that the capture includes the full handshake

### Encrypted Application Data
- After the handshake, application data is encrypted
- You can see packet sizes and timing, but not content
- This is expected behavior - TLS provides confidentiality

## Security Notes

- TLS handshakes are designed to be secure even if captured
- The pre-master secret is encrypted and cannot be decrypted without the server's private key
- Certificate chains can be verified to ensure authenticity
- Modern TLS (1.2+) uses strong cipher suites and key exchange methods

## Additional Resources

- Wireshark TLS Documentation: https://www.wireshark.org/docs/wsug_html_chunked/ChWorkDisplayFilterSection.html
- TLS 1.2 RFC: https://tools.ietf.org/html/rfc5246
- TLS 1.3 RFC: https://tools.ietf.org/html/rfc8446

