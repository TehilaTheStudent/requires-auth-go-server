# PowerShell script to generate certificates using OpenSSL
# Make sure OpenSSL is installed and in PATH

# Create certificates directory
New-Item -ItemType Directory -Force -Path "certs"

Write-Host "Generating CA private key..."
& openssl genrsa -out certs/ca-key.pem 4096

Write-Host "Generating CA certificate..."
& openssl req -new -x509 -days 365 -key certs/ca-key.pem -sha256 -out certs/ca-cert.pem -subj "/C=US/ST=CA/L=San Francisco/O=Test CA/CN=Test CA"

Write-Host "Generating server private key..."
& openssl genrsa -out certs/server-key.pem 4096

Write-Host "Generating server certificate signing request..."
& openssl req -subj "/C=US/ST=CA/L=San Francisco/O=Test Server/CN=localhost" -new -key certs/server-key.pem -out certs/server.csr

Write-Host "Creating server extensions file..."
@"
subjectAltName=DNS:localhost,IP:127.0.0.1
"@ | Out-File -FilePath "certs/server-ext.conf" -Encoding ASCII

Write-Host "Generating server certificate signed by CA..."
& openssl x509 -req -days 365 -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -out certs/server-cert.pem -extensions v3_req -extfile certs/server-ext.conf

Write-Host "Generating client private key..."
& openssl genrsa -out certs/client-key.pem 4096

Write-Host "Generating client certificate signing request..."
& openssl req -subj "/C=US/ST=CA/L=San Francisco/O=Test Client/CN=client" -new -key certs/client-key.pem -out certs/client.csr

Write-Host "Generating client certificate signed by CA..."
& openssl x509 -req -days 365 -in certs/client.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -out certs/client-cert.pem

Write-Host "Cleaning up temporary files..."
Remove-Item certs/server.csr, certs/client.csr, certs/server-ext.conf

Write-Host "Certificates generated successfully!"
Write-Host "CA Certificate: certs/ca-cert.pem"
Write-Host "Server Certificate: certs/server-cert.pem"
Write-Host "Server Key: certs/server-key.pem"
Write-Host "Client Certificate: certs/client-cert.pem"
Write-Host "Client Key: certs/client-key.pem"
