# NGINX Certificate Manager

A comprehensive tool for automating SSL certificate management for NGINX servers, including issuance, renewal, and deployment.

## Features

- **Certificate Issuance**: Obtain SSL certificates from Let's Encrypt using DNS validation
- **Route53 Integration**: Automatic DNS challenge handling with AWS Route53
- **Certificate Renewal**: Automatic renewal of certificates before expiration
- **Certificate Deployment**: Securely deploy certificates to NGINX servers
- **Command-line Interface**: Easy-to-use CLI for all operations
- **Configuration Management**: Support for environment variables and config files

## Installation

```bash
# Clone the repository
git clone https://github.com/tunghauvan/nginx-cert-manager.git
cd nginx-cert-manager

# Install by kubectl
```bash
kubectl apply -f k8s
```

# Test example resource
```bash
kubectl apply -f example/sample-domaincertificate.yaml
```