# Public Key Infrastructure Lab - Write-Up

**Student Name:** Matthew Ondeyo
**Date:** October 17, 2025

---

## Overview

This lab demonstrates the security vulnerabilities of unencrypted HTTP communication and shows how HTTPS with TLS encryption addresses these vulnerabilities. Through packet capture and analysis, we observe how sensitive data can be intercepted over HTTP and how encryption protects against such attacks.

---

## Task 1: Host a Local Web Server

### Implementation

I set up a local web server using Python's `http.server` module. The server runs on `localhost:8000` and serves a simple HTML page with a login form.

**Server Details:**
- **Technology:** Python 3.12.1 HTTP server
- **Port:** 8000
- **Protocol (Initial):** HTTP (unencrypted)
- **Files Created:**
  - `http_server.py` - HTTP server implementation
  - `index.html` - Web page with login form

The server includes a POST endpoint that accepts form submissions containing username and password fields, which are logged to the console and displayed back to the user.

**Command to run:**
```bash
python3 http_server.py
```

The server successfully started and was accessible at `http://localhost:8000`.

---

## Task 2: Identify Why HTTP is Not Secure

### Security Vulnerabilities of HTTP

HTTP (Hypertext Transfer Protocol) is fundamentally insecure because **all communication is transmitted in plain text**. This means that any data sent between a client (web browser) and server—including usernames, passwords, personal information, and browsing activity—can be intercepted and read by anyone who has access to the network traffic.

### How Eavesdropping Works

An attacker can use **packet sniffing** to intercept HTTP traffic. Packet sniffers are tools that capture network packets traveling across a network. Since HTTP does not encrypt data, these captured packets reveal all transmitted information in readable form.

**Attack Scenarios:**
1. **Man-in-the-Middle (MITM) Attack:** An attacker positions themselves between the client and server to intercept communications
2. **Network Sniffing:** On shared networks (public WiFi, compromised routers), attackers can capture all unencrypted traffic
3. **ISP/Network Administrator Monitoring:** Anyone with access to network infrastructure can read HTTP traffic

### Packet Capture Analysis - HTTP Traffic

Using Wireshark, I captured network traffic between my browser and the HTTP server while submitting credentials through the login form.

**Test Data Submitted:**
- Username: `ondeyo`
- Password: `swagsauce`

**Key Findings from HTTP Capture:**

1. **Visible Request Method:** The POST request to `/submit` is clearly visible in the packet list
2. **Plain Text Headers:** All HTTP headers (User-Agent, Host, Content-Type, etc.) are readable
3. **Exposed Form Data:** In the packet details, the form data is completely visible:
   ```
   Form URL Encoded: application/x-www-form-urlencoded
   Form item: "username" = "ondeyo"
   Form item: "password" = "swagsauce"
   ```
4. **No Encryption:** The entire HTTP payload can be read without any decryption

**Screenshot Evidence:** See `http_capture.pcapng` - The bottom panel of Wireshark clearly shows the username and password in plain text within the HTTP POST request body.

### Security Implications

This demonstrates that HTTP provides:
- ❌ **No confidentiality:** Data can be read by eavesdroppers
- ❌ **No integrity:** Data can be modified in transit without detection
- ❌ **No authentication:** No verification that you're communicating with the intended server

Any sensitive information transmitted over HTTP is vulnerable to interception, making it unsuitable for any application requiring security or privacy.

---

## Task 3: Create Self-Signed Certificate and Upgrade to HTTPS

### Part A: Why Can't You Obtain an SSL Certificate from a CA for Localhost?

Certificate Authorities (CAs) cannot and will not issue SSL certificates for `localhost` or private IP addresses for several important reasons:

1. **No Unique Ownership:** `localhost` (127.0.0.1) is a reserved address that refers to the local computer on every machine. There is no way to prove unique ownership of "localhost" since everyone's computer uses the same address.

2. **Domain Validation Requirements:** CAs must verify that the certificate requester has control over the domain name. Since `localhost` is not a unique domain but a universal loopback address, this validation is impossible.

3. **Security Concerns:** If a CA issued a certificate for `localhost`, it could be misused. Any attacker could use that certificate on their own machine to create seemingly "legitimate" HTTPS sites that are actually malicious.

4. **CA/Browser Forum Baseline Requirements:** Industry standards explicitly prohibit CAs from issuing certificates for:
   - Reserved IP addresses (127.0.0.0/8, including localhost)
   - Internal domain names
   - Domains the applicant doesn't control

**Solution:** For local development and testing, developers must create **self-signed certificates**—certificates that are not verified by a trusted CA but still enable encryption.

### Generating a Self-Signed Certificate

I used OpenSSL to generate a self-signed SSL certificate for localhost:

**Command:**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=US/ST=Illinois/L=Chicago/O=SecurityLab/CN=localhost"
```

**Parameters Explained:**
- `-x509`: Create a self-signed certificate instead of a certificate request
- `-newkey rsa:4096`: Generate a new 4096-bit RSA private key
- `-keyout key.pem`: Save the private key to this file
- `-out cert.pem`: Save the certificate to this file
- `-days 365`: Certificate valid for 1 year
- `-nodes`: Don't encrypt the private key (no password required)
- `-subj`: Certificate subject information (Common Name = localhost)

**Files Generated:**
- `cert.pem` - The SSL certificate (public)
- `key.pem` - The private key (keep secure)

### Adding Certificate to Trusted Roots

To avoid browser warnings during testing, I added the self-signed certificate to macOS's trusted root certificates:

**Command:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.pem
```

This adds the certificate to the system keychain and marks it as trusted for SSL/TLS.

**Note:** Even after adding to trusted roots, Chrome may still show warnings because self-signed certificates don't have the full chain of trust that CA-issued certificates provide.

### Upgrading Server to HTTPS

I created an HTTPS version of the web server (`https_server.py`) that uses Python's `ssl` module to wrap the socket with TLS encryption:

**Key Changes:**
```python
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
```

The server now runs on `https://localhost:8000` and encrypts all communication using TLS 1.3.

### Packet Capture Analysis - HTTPS Traffic

Using Wireshark, I captured network traffic while submitting the same credentials over HTTPS.

**Key Findings from HTTPS Capture:**

1. **TLS Handshake:** The capture shows TLSv1.3 handshake packets establishing the encrypted connection
2. **Encrypted Application Data:** All HTTP payload is now transmitted as "Application Data" in TLS
3. **No Visible Credentials:** Unlike HTTP, the username and password are **not visible** in any packet
4. **Binary Encrypted Content:** The packet payload shows only encrypted binary data

**Screenshot Evidence:** See `https_capture.pcapng` - The packets show TLSv1.3 protocol with Application Data, but no readable form data.

### Comparison: HTTP vs HTTPS Traffic

| Aspect | HTTP | HTTPS (TLS) |
|--------|------|-------------|
| **Protocol** | HTTP | TLSv1.3 |
| **Encryption** | None | AES-256-GCM or similar |
| **Credentials Visible** | ✅ Yes, plain text | ❌ No, encrypted |
| **Headers Visible** | ✅ Yes, all readable | ❌ Only TLS handshake visible |
| **Form Data Visible** | ✅ Yes, fully exposed | ❌ No, encrypted as Application Data |
| **Packet Content** | Readable ASCII/text | Encrypted binary data |
| **Integrity Protection** | ❌ None | ✅ Yes, HMAC verification |
| **Authentication** | ❌ None | ✅ Yes, certificate-based |

### How HTTPS Protects Data

HTTPS (HTTP Secure) uses **TLS (Transport Layer Security)** to provide:

1. **Encryption:** All data is encrypted using strong cryptographic algorithms, making it unreadable to eavesdroppers
2. **Integrity:** Cryptographic checksums ensure data hasn't been tampered with in transit
3. **Authentication:** SSL certificates verify the server's identity (when signed by trusted CA)

Even if an attacker captures HTTPS packets, they see only encrypted binary data. Without the encryption keys (which are negotiated during the TLS handshake), the data cannot be decrypted.

---

## Conclusions

This lab clearly demonstrates the critical security differences between HTTP and HTTPS:

1. **HTTP is fundamentally insecure** - All data, including passwords and sensitive information, is transmitted in plain text and can be easily intercepted

2. **Packet sniffing is trivial** - Tools like Wireshark make it simple to capture and read HTTP traffic on any network

3. **HTTPS provides essential protection** - TLS encryption renders captured data useless to attackers without the encryption keys

4. **Self-signed certificates enable encryption** - While not trusted by default, self-signed certificates still provide the encryption benefits of HTTPS for development and testing

5. **Certificate Authorities serve a critical role** - CAs provide the trust infrastructure that validates server identities, preventing man-in-the-middle attacks

**Practical Implications:**
- Never transmit sensitive data over HTTP
- Always use HTTPS for any website handling user credentials or personal information
- Public WiFi networks are particularly dangerous for HTTP traffic
- Modern browsers increasingly warn users about or block HTTP sites

---

## Files Included in Submission

1. **writeup.md** - This document
2. **http_capture.pcapng** - Wireshark packet capture of HTTP traffic showing plain text credentials
3. **https_capture.pcapng** - Wireshark packet capture of HTTPS traffic showing encrypted data


---

## References

- Python http.server documentation: https://docs.python.org/3/library/http.server.html
- OpenSSL documentation: https://www.openssl.org/docs/
- Wireshark User Guide: https://www.wireshark.org/docs/wsug_html/
- TLS 1.3 Specification: RFC 8446
- CA/Browser Forum Baseline Requirements: https://cabforum.org/baseline-requirements/
