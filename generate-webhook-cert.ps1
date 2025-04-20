# Define variables
$serviceName = "webhook-service" # Replace with your Kubernetes Service name
$namespace = "nginx-cert-manager" # Replace with your Kubernetes Namespace
$keyFile = "tls.key"
$csrFile = "tls.csr"
$crtFile = "tls.crt"
$confFile = "csr.conf"
$validityDays = 365

# --- Generate Private Key ---
Write-Host "Generating private key ($keyFile)..."
openssl genrsa -out $keyFile 2048

# --- Create CSR Configuration ---
Write-Host "Creating CSR configuration ($confFile)..."
$csrConfig = @"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $serviceName.$namespace.svc

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $serviceName
DNS.2 = $serviceName.$namespace
DNS.3 = $serviceName.$namespace.svc
"@
Set-Content -Path $confFile -Value $csrConfig

# --- Generate CSR ---
Write-Host "Generating Certificate Signing Request ($csrFile)..."
openssl req -new -key $keyFile -out $csrFile -config $confFile

# --- Generate Self-Signed Certificate ---
Write-Host "Generating self-signed certificate ($crtFile)..."
openssl x509 -req -days $validityDays -in $csrFile -signkey $keyFile -out $crtFile -extensions v3_req -extfile $confFile

# --- Base64 Encode Certificate and Key ---
Write-Host "Base64 encoding certificate and key..."
$base64Crt = [Convert]::ToBase64String([IO.File]::ReadAllBytes($crtFile))
$base64Key = [Convert]::ToBase64String([IO.File]::ReadAllBytes($keyFile))

# --- Output Results ---
Write-Host "`n--- Generated Files ---"
Write-Host "Private Key: $keyFile"
Write-Host "Certificate: $crtFile"

Write-Host "`n--- Base64 Encoded Output ---"
Write-Host "Update your 'webhook-tls-secret.yaml' with these values:"
Write-Host "`ntls.crt:"
Write-Host $base64Crt
Write-Host "`ntls.key:"
Write-Host $base64Key

# --- Cleanup (Optional) ---
# Read-Host -Prompt "Press Enter to cleanup temporary files ($csrFile, $confFile) or Ctrl+C to keep them"
# Remove-Item $csrFile
# Remove-Item $confFile
# Write-Host "Temporary files removed."

Write-Host "`nScript finished."
