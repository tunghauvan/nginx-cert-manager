import os
import boto3
import logging

logger = logging.getLogger("nginx-cert-manager.s3")

def upload_cert_to_s3(domain, cert_dir, s3_bucket=None):
    """
    Upload certificate files to S3 bucket
    
    Args:
        domain (str): The domain name for the certificate
        cert_dir (str): Directory containing the certificate files
        s3_bucket (str): Optional - S3 bucket name (defaults to env var)
        
    Returns:
        bool: True if upload successful, False otherwise
    """
    try:
        s3_bucket = s3_bucket or os.environ.get("S3_CERT_BUCKET", "accesstrade-server-configs")
        s3_prefix = f"certs/{domain}/"  # Use domain-specific folder
        
        logger.info(f"Uploading certificate files for {domain} to S3 bucket {s3_bucket}/{s3_prefix}")
        
        s3_client = boto3.client('s3')
        
        # Upload certificate files
        cert_path = os.path.join(cert_dir, f"{domain}.crt")
        key_path = os.path.join(cert_dir, f"{domain}.key")
        chain_path = os.path.join(cert_dir, f"{domain}.chain.crt")
        
        # Upload to domain-specific folders
        s3_client.upload_file(
            cert_path, 
            s3_bucket, 
            f"{s3_prefix}{domain}.crt"
        )
        
        s3_client.upload_file(
            key_path, 
            s3_bucket, 
            f"{s3_prefix}{domain}.key"
        )
        
        s3_client.upload_file(
            chain_path, 
            s3_bucket, 
            f"{s3_prefix}{domain}.chain.crt"
        )
        
        logger.info(f"Successfully uploaded certificate files for {domain} to S3 folder {s3_prefix}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload certificate files to S3: {e}")
        return False
