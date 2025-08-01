#!/bin/bash

# Create certificates directory
mkdir -p certs

# Generate CA private key
openssl genrsa -out certs/ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key certs/ca-key.pem -sha256 -out certs/ca-cert.pem -subj "/C=US/ST=CA/L=San Francisco/O=Test CA/CN=Test CA"

# Generate server private key
openssl genrsa -out certs/server-key.pem 4096

# Generate server certificate signing request
openssl req -subj "/C=US/ST=CA/L=San Francisco/O=Test Server/CN=localhost" -new -key certs/server-key.pem -out certs/server.csr

# Generate server certificate signed by CA
openssl x509 -req -days 365 -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -out certs/server-cert.pem -extensions v3_req -extfile <(echo -e "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Generate client private key
openssl genrsa -out certs/client-key.pem 4096

# Generate client certificate signing request
openssl req -subj "/C=US/ST=CA/L=San Francisco/O=Test Client/CN=client" -new -key certs/client-key.pem -out certs/client.csr

# Generate client certificate signed by CA
openssl x509 -req -days 365 -in certs/client.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -out certs/client-cert.pem

# Clean up CSR files
rm certs/server.csr certs/client.csr

echo "Certificates generated successfully!"
echo "CA Certificate: certs/ca-cert.pem"
echo "Server Certificate: certs/server-cert.pem"
echo "Server Key: certs/server-key.pem"
echo "Client Certificate: certs/client-cert.pem"
echo "Client Key: certs/client-key.pem"
