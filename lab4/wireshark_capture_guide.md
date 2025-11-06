# Wireshark TLS Handshake Capture Guide

## Prerequisites
- Wireshark installed (download from https://www.wireshark.org/)
- Administrator/root privileges (for packet capture)

## Step-by-Step Instructions

### 1. Starting Wireshark Capture

#### Windows:
1. Open Wireshark as Administrator
2. Select your network interface (usually "Wi-Fi" or "Ethernet")
3. Click the blue shark fin icon to start capturing

#### Linux/Mac:
```bash
# Start Wireshark from terminal
sudo wireshark

# Or use tcpdump from command line
sudo tcpdump -i any -w tls_handshake.pcap -s 0 'tcp port 443'
```

### 2. Filtering for HTTPS/TLS Traffic

In Wireshark's filter bar, use one of these filters:
- `tls` - Shows all TLS packets
- `tcp.port == 443` - Shows all HTTPS traffic
- `ssl` - Alternative filter for SSL/TLS
- `tls.handshake.type == 1` - Client Hello
- `tls.handshake.type == 2` - Server Hello

### 3. Capturing a Specific Website

1. **Before starting capture:**
   - Open a new browser window (or use incognito/private mode)
   - Clear browser cache if needed

2. **Start capture in Wireshark**

3. **Navigate to a website:**
   - Go to https://www.google.com (or any HTTPS site)
   - Wait for the page to load completely

4. **Stop capture** (red square button)

### 4. Analyzing the TLS Handshake

#### Key Packets to Look For:

1. **TCP Three-Way Handshake** (SYN, SYN-ACK, ACK)
   - Establishes TCP connection before TLS

2. **TLS Client Hello** (Packet with `Handshake Protocol: Client Hello`)
   - Client sends:
     - TLS version supported
     - Cipher suites offered
     - Random number (Client Random)
     - Compression methods
     - Extensions (SNI, etc.)

3. **TLS Server Hello** (Packet with `Handshake Protocol: Server Hello`)
   - Server responds with:
     - Selected TLS version
     - Selected cipher suite
     - Random number (Server Random)
     - Session ID

4. **Certificate** (Packet with `Handshake Protocol: Certificate`)
   - Server sends its certificate chain
   - Contains public key, issuer, validity

5. **Server Key Exchange** (if applicable)
   - Additional key exchange parameters

6. **Server Hello Done**
   - Indicates server finished sending handshake messages

7. **Client Key Exchange**
   - Client sends pre-master secret (encrypted with server's public key)

8. **Change Cipher Spec**
   - Both sides switch to encrypted communication

9. **Encrypted Handshake Message**
   - First encrypted messages
   - Application data follows

### 5. Exporting Capture

1. Go to **File → Export Specified Packets**
2. Select the TLS handshake packets
3. Save as `tls_handshake.pcap` or `tls_handshake.pcapng`

### 6. Taking Screenshots

Capture screenshots of:
- **Full TLS handshake sequence** (packet list view)
- **Client Hello details** (expand packet details)
- **Server Hello details** (expand packet details)
- **Certificate details** (expand certificate packet)
- **Cipher suite selection** (in Server Hello)

### 7. Using tcpdump (Command Line Alternative)

```bash
# Capture TLS handshake
sudo tcpdump -i any -w tls_handshake.pcap -s 0 'tcp port 443'

# In another terminal, visit a website
curl https://www.google.com

# Stop tcpdump (Ctrl+C)

# Analyze with tcpdump
tcpdump -r tls_handshake.pcap -A -n 'tcp port 443'

# Or open in Wireshark
wireshark tls_handshake.pcap
```

### 8. Filtering Specific Handshake Messages

In Wireshark display filter:
- `tls.handshake.type == 1` - Client Hello
- `tls.handshake.type == 2` - Server Hello
- `tls.handshake.type == 11` - Certificate
- `tls.handshake.type == 12` - Server Hello Done
- `tls.handshake.type == 16` - Client Key Exchange

### 9. Analyzing Cipher Suite

1. Find Server Hello packet
2. Expand: `TLSv1.2 Record Layer: Handshake Protocol: Server Hello`
3. Look for: `Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (example)
4. This shows:
   - Key Exchange: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
   - Authentication: RSA
   - Encryption: AES-128-GCM
   - MAC: SHA256

### 10. Verifying Certificate Chain

1. Find Certificate packet
2. Expand certificate details
3. Check:
   - Subject (website name)
   - Issuer (Certificate Authority)
   - Validity dates
   - Public key algorithm

## Troubleshooting

- **No packets captured:** Check interface selection and permissions
- **Can't see TLS details:** Ensure you're capturing on the correct interface
- **Handshake not visible:** Try clearing browser cache and capturing fresh connection

