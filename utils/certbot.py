import os
import logging
from utils.s3 import upload_cert_to_s3
from utils.certbot_runner import run_certbot
from utils.cert_handler import copy_certificates

logger = logging.getLogger("nginx-cert-manager.certbot")

def request_certificate(domain, email,
                       dns_plugin=None,
                       config_dir=None,
                       log_dir=None,
                       cert_output_dir=None):
    """
    Request a certificate using Certbot with DNS challenge, copy it, and upload to S3.

    Args:
        domain (str): Domain name to request a certificate for
        email (str): Email address for certificate registration
        dns_plugin (str): DNS plugin to use (e.g., dns-route53)
        config_dir (str): Certbot config directory
        log_dir (str): Certbot log directory
        cert_output_dir (str): Output directory for certificates (e.g., for Nginx)

    Returns:
        bool: True if certificate was obtained and processed successfully, False otherwise
    """
    logger.info(f"Starting certificate request process for {domain}")
    try:
        # Get settings from parameters or environment
        dns_plugin = dns_plugin or os.environ.get("CERTBOT_DNS_PLUGIN", "dns-route53")
        certbot_config_dir = config_dir or os.environ.get("CERTBOT_CONFIG_DIR", "/etc/certbot")
        certbot_log_dir = log_dir or os.environ.get("CERTBOT_LOG_DIR", "/var/log/certbot")
        nginx_cert_dir = cert_output_dir or os.environ.get("CERT_OUTPUT_DIR", "/etc/nginx/ssl")

        # Ensure required directories exist
        # Certbot runner might handle its own dirs, but good to ensure they exist beforehand
        os.makedirs(nginx_cert_dir, exist_ok=True)
        os.makedirs(certbot_config_dir, exist_ok=True)
        os.makedirs(certbot_log_dir, exist_ok=True)

        # Run certbot command using the dedicated runner
        result = run_certbot(domain, email, dns_plugin, certbot_config_dir, certbot_log_dir)

        if result.returncode != 0:
            logger.error(f"Certbot command failed for {domain}. Return code: {result.returncode}")
            logger.error(f"Certbot stderr: {result.stderr}")
            logger.debug(f"Certbot stdout: {result.stdout}")
            return False

        logger.info(f"Certbot successfully obtained certificate for {domain}.")
        logger.debug(f"Certbot stdout: {result.stdout}")

        # Copy certificates to the target directory using the dedicated handler
        if not copy_certificates(domain, certbot_config_dir, nginx_cert_dir):
            logger.error(f"Failed to copy certificate files for {domain} to {nginx_cert_dir}")
            return False # Treat copy failure as overall failure

        logger.info(f"Certificate files copied to {nginx_cert_dir} for {domain}")

        # Upload certificates to S3
        if upload_cert_to_s3(domain, nginx_cert_dir):
            logger.info(f"Certificate files for {domain} uploaded to S3 successfully")
        else:
            # Decide if S3 upload failure should cause the whole process to fail
            # Currently warning and returning True as cert was obtained and copied
            logger.error(f"Failed to upload certificate files for {domain} to S3")
            return False

        return True
    except Exception as e:
        logger.exception(f"An unexpected error occurred during the certificate request process for {domain}: {e}")
        return False
