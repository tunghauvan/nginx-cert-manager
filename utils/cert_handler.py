import os
import logging
import shutil

logger = logging.getLogger("nginx-cert-manager.cert_handler")

def copy_certificates(domain, certbot_config_dir, target_cert_dir):
    """
    Copies certificate files from Certbot's live directory to the target directory.

    Args:
        domain (str): The domain name.
        certbot_config_dir (str): Certbot's main configuration directory (e.g., /etc/certbot).
        target_cert_dir (str): The directory to copy the certificates to (e.g., /etc/nginx/ssl).

    Returns:
        bool: True if copying was successful, False otherwise.
    """
    cert_name = domain.replace(".", "-")
    live_dir = os.path.join(certbot_config_dir, "live", cert_name)

    cert_files = {
        "fullchain.pem": f"{domain}.crt",
        "privkey.pem": f"{domain}.key",
        "chain.pem": f"{domain}.chain.crt"
    }

    try:
        os.makedirs(target_cert_dir, exist_ok=True)
        copied_count = 0
        for src_name, dest_name in cert_files.items():
            src_path = os.path.join(live_dir, src_name)
            dest_path = os.path.join(target_cert_dir, dest_name)

            if os.path.exists(src_path):
                shutil.copy2(src_path, dest_path) # copy2 preserves metadata
                logger.debug(f"Copied {src_path} to {dest_path}")
                copied_count += 1
            else:
                logger.error(f"Source certificate file not found: {src_path}")
                return False # Fail if any essential file is missing

        if copied_count == len(cert_files):
            logger.info(f"Certificate files for {domain} copied successfully to {target_cert_dir}")
            return True
        else:
            # This case should ideally be caught by the check above, but added for safety
            logger.error(f"Failed to copy all certificate files for {domain} from {live_dir}")
            return False

    except Exception as e:
        logger.error(f"Error copying certificate files for {domain}: {e}")
        return False
