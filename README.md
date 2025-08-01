# Go Server with Client Certificate Authentication

This project demonstrates a Go HTTPS server that requires client certificate authentication (mutual TLS). It returns JSON responses and provides massive logging for every request including detailed client certificate information. It's designed for troubleshooting client key and certificate issues.

## Files Structure

```
├── main.go              # Main server application with JSON responses and massive logging
├── go.mod              # Go module file
├── Dockerfile          # Docker configuration
├── generate-certs.ps1  # PowerShell script to generate certificates (Windows)
├── generate-certs.sh   # Bash script to generate certificates (Linux/Mac)
└── certs/              # Directory containing all certificates (created after running cert generation)
    ├── ca-cert.pem     # Certificate Authority certificate
    ├── ca-key.pem      # Certificate Authority private key
    ├── server-cert.pem # Server certificate
    ├── server-key.pem  # Server private key
    ├── client-cert.pem # Client certificate
    └── client-key.pem  # Client private key
```

## Quick Start

### 1. Generate Certificates

**On Windows (PowerShell):**
```powershell
.\generate-certs.ps1
```

**On Linux/Mac (Bash):**
```bash
chmod +x generate-certs.sh
./generate-certs.sh
```

### 2. Run the Server

```bash
go run main.go
```

The server will start on `https://localhost:8443` and will log massive details for every request including:
- Complete request headers
- TLS connection details
- Client certificate information (if provided)
- Certificate chain verification details
- Request timing

### 4. Test with curl

```bash
# Test with client certificate
curl -k --cert certs/client-cert.pem --key certs/client-key.pem https://localhost:8443/

# Test without client certificate (should fail)
curl -k https://localhost:8443/
```

## Docker Usage

### Build the Docker image:
```bash
docker build -t secure-go-server .
```

### Run the container:
```bash
docker run -p 8443:8443 secure-go-server
```

## Endpoints

All endpoints return JSON responses and require client certificate authentication:

- `GET /` - Root endpoint with client certificate details and request info
- `GET /secure` - Detailed endpoint with comprehensive client certificate and TLS information
- `GET /health` - Health check endpoint with server status and client cert info

## Certificate Details

- **CA Certificate**: Self-signed root certificate authority
- **Server Certificate**: Signed by CA, valid for `localhost` and `127.0.0.1`
- **Client Certificate**: Signed by CA, used for client authentication

## Troubleshooting

### Common Issues:

1. **Certificate not found errors**: Make sure to run the certificate generation script first
2. **Connection refused**: Ensure the server is running on port 8443
3. **Certificate verification failed**: Check that the client certificate is signed by the same CA as expected by the server
4. **Hostname mismatch**: Make sure you're connecting to `localhost` (not `127.0.0.1` in the URL if using curl)

### Testing the server:

You can use curl to test the endpoints:
```bash
# Test with client certificate
curl -k --cert certs/client-cert.pem --key certs/client-key.pem https://localhost:8443/
curl -k --cert certs/client-cert.pem --key certs/client-key.pem https://localhost:8443/secure
curl -k --cert certs/client-cert.pem --key certs/client-key.pem https://localhost:8443/health

# Test without client certificate (should fail)
curl -k https://localhost:8443/
```

You can also use OpenSSL to test the connection:
```bash
openssl s_client -connect localhost:8443 -cert certs/client-cert.pem -key certs/client-key.pem -CAfile certs/ca-cert.pem
```

## Security Notes

- This is for development/testing purposes only
- In production, use proper certificate management
- The CA private key should be kept secure and not distributed
- Consider using shorter certificate validity periods in production
