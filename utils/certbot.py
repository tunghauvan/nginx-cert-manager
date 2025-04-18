import os
import subprocess
import logging
from utils.s3 import upload_cert_to_s3

logger = logging.getLogger("nginx-cert-manager.certbot")

def request_certificate(domain, email, 
                       dns_plugin=None, 
                       config_dir=None, 
                       log_dir=None, 
                       cert_output_dir=None):
    """
    Request a certificate using Certbot with DNS challenge.
    
    Args:
        domain (str): Domain name to request a certificate for
        email (str): Email address for certificate registration
        dns_plugin (str): DNS plugin to use (e.g., dns-route53)
        config_dir (str): Certbot config directory
        log_dir (str): Certbot log directory
        cert_output_dir (str): Output directory for certificates
        
    Returns:
        bool: True if certificate was obtained successfully, False otherwise
    """
    logger.info(f"Requesting certificate for {domain} using Certbot with DNS challenge")
    try:
        # Get settings from parameters or environment
        dns_plugin = dns_plugin or os.environ.get("CERTBOT_DNS_PLUGIN", "dns-route53")
        config_dir = config_dir or os.environ.get("CERTBOT_CONFIG_DIR", "/etc/certbot")
        log_dir = log_dir or os.environ.get("CERTBOT_LOG_DIR", "/var/log/certbot")
        cert_dir = cert_output_dir or os.environ.get("CERT_OUTPUT_DIR", "/etc/nginx/ssl")
        
        # Ensure output directories exist
        os.makedirs(cert_dir, exist_ok=True)
        os.makedirs(config_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)
        
        # Build the certbot command
        cmd = [
            "certbot", "certonly", "--non-interactive",
            "--agree-tos", "--email", email,
            "--preferred-challenges", "dns",
            f"--{dns_plugin}",
            "-d", domain,
            "--cert-name", domain.replace(".", "-"),
            "--config-dir", config_dir,
            "--logs-dir", log_dir,
            "--force-renewal"
        ]
        
        # Run certbot command
        logger.info(f"Running certbot command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False  # Don't raise exception, we'll handle errors manually
        )
        
        if result.returncode != 0:
            logger.error(f"Certbot command failed: {result.stderr}")
            return False
        
        logger.info(f"Certbot successfully obtained certificate: {result.stdout}")
        
        # Certbot puts certificates in a specific directory structure
        # Copy the certificates to our desired location
        cert_path = os.path.join(
            config_dir, "live", domain.replace(".", "-"), "fullchain.pem"
        )
        key_path = os.path.join(
            config_dir, "live", domain.replace(".", "-"), "privkey.pem"
        )
        chain_path = os.path.join(
            config_dir, "live", domain.replace(".", "-"), "chain.pem"
        )
        
        # Copy certificates to nginx directory
        with open(cert_path, 'r') as src_file, open(os.path.join(cert_dir, f"{domain}.crt"), 'w') as dest_file:
            dest_file.write(src_file.read())
            
        with open(key_path, 'r') as src_file, open(os.path.join(cert_dir, f"{domain}.key"), 'w') as dest_file:
            dest_file.write(src_file.read())
            
        with open(chain_path, 'r') as src_file, open(os.path.join(cert_dir, f"{domain}.chain.crt"), 'w') as dest_file:
            dest_file.write(src_file.read())
            
        logger.info(f"Certificate files copied to {cert_dir} for {domain}")
        
        # Upload certificates to S3
        if upload_cert_to_s3(domain, cert_dir):
            logger.info(f"Certificate files for {domain} uploaded to S3 successfully")
        else:
            logger.warning(f"Failed to upload certificate files for {domain} to S3, but continuing...")
        
        return True
    except Exception as e:
        logger.error(f"Failed to request certificate for {domain}: {e}")
        return False
