import os
import json
import logging
import pika
import time
from dotenv import load_dotenv
from utils.sshagent import SSHAgent

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("cert-success-worker")

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", 5672))
RABBITMQ_USER = os.environ.get("RABBITMQ_DEFAULT_USER", "user")
RABBITMQ_PASS = os.environ.get("RABBITMQ_DEFAULT_PASS", "password")
QUEUE_NAME_SUCCESS = "cert_success"

# Add environment variables for SSH and S3 paths
SSH_HOST = os.environ.get("SSH_HOST", "172.31.35.222")
SSH_PORT = int(os.environ.get("SSH_PORT", 22))
SSH_USER = os.environ.get("SSH_USER", "ubuntu")
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/root/.ssh/key.pem")
S3_CERT_BUCKET = os.environ.get("S3_CERT_BUCKET", "accesstrade-server-configs")

def process_success_event(body):
    """Process a certificate success event."""
    try:
        data = json.loads(body)
        domain = data.get("domain")
        status = data.get("status")
        
        if not domain or status != "success":
            logger.error(f"Invalid success event data: {data}")
            return False
        
        logger.info(f"Processing success event for domain: {domain}")
        
        # Initialize SSH connection to deploy certificate
        ssh = SSHAgent()
        try:
            # Connect to remote server
            connection = ssh.connect(
                hostname=SSH_HOST,
                port=SSH_PORT,
                username=SSH_USER,
                key_filename=SSH_KEY_PATH
            )
            
            if not connection:
                logger.error(f"Failed to connect to SSH server {SSH_HOST}")
                return False
                
            # Create certificate directory if it doesn't exist
            target_dir = f"/etc/letsencrypt/live/{domain}"
            command = f"sudo mkdir -p {target_dir}"
            exit_code, stdout, stderr = ssh.execute_command(command)
            
            if exit_code != 0:
                logger.error(f"Failed to create directory {target_dir}: {stderr}")
                return False
            
            # Upload the certificate files
            # Fullchain certificate
            s3_cert_path = f"s3://{S3_CERT_BUCKET}/certs/{domain}/{domain}.crt"
            temp_remote_path = f"/tmp/fullchain.pem"
            final_remote_path = f"{target_dir}/fullchain.pem"
            
            if not ssh.upload_from_s3_to_remote(s3_cert_path, temp_remote_path):
                logger.error("Certificate upload failed")
                return False
                
            logger.info(f"Certificate uploaded to temporary location {temp_remote_path}")
            
            # Move the certificate file to the final destination with sudo and set permissions
            move_command = f"sudo cp {temp_remote_path} {final_remote_path} && sudo chmod 644 {final_remote_path} && rm {temp_remote_path}"
            exit_code, stdout, stderr = ssh.execute_command(move_command)
            
            if exit_code != 0:
                logger.error(f"Failed to move certificate to final destination: {stderr}")
                return False
                
            logger.info(f"Certificate successfully deployed to {final_remote_path}")
            
            # Process the private key file
            s3_key_path = f"s3://{S3_CERT_BUCKET}/certs/{domain}/{domain}.key"
            temp_key_path = f"/tmp/privkey.pem"
            final_key_path = f"{target_dir}/privkey.pem"
            
            if not ssh.upload_from_s3_to_remote(s3_key_path, temp_key_path):
                logger.error("Private key upload failed")
                return False
                
            logger.info(f"Private key uploaded to temporary location {temp_key_path}")
            
            # Move the key file to the final destination with sudo and set more restrictive permissions
            move_key_command = f"sudo cp {temp_key_path} {final_key_path} && sudo chmod 600 {final_key_path} && rm {temp_key_path}"
            exit_code, stdout, stderr = ssh.execute_command(move_key_command)
            
            if exit_code != 0:
                logger.error(f"Failed to move private key to final destination: {stderr}")
                return False
                
            logger.info(f"Private key successfully deployed to {final_key_path}")
            
            # Reload Nginx or other web server if needed
            reload_command = "sudo systemctl reload nginx"
            exit_code, stdout, stderr = ssh.execute_command(reload_command)
            if exit_code != 0:
                logger.warning(f"Failed to reload nginx: {stderr}")
            else:
                logger.info("Nginx reloaded successfully")
            
            logger.info(f"Success event for {domain} processed completely")
            return True
                
        finally:
            # Ensure SSH connection is closed
            ssh.disconnect()
        
    except Exception as e:
        logger.error(f"Failed to process success event: {e}")
        return False

def main():
    """Main function to consume success events from RabbitMQ."""
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    parameters = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=credentials
    )
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME_SUCCESS, durable=True)

    def callback(ch, method, properties, body):
        if process_success_event(body):
            ch.basic_ack(delivery_tag=method.delivery_tag)
        else:
            # For success events, if processing fails, we don't want to retry forever
            logger.warning("Failed to process success event, acknowledging anyway")
            ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME_SUCCESS, on_message_callback=callback)

    logger.info(f"Waiting for success events in queue '{QUEUE_NAME_SUCCESS}'. To exit press CTRL+C")
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    finally:
        connection.close()

if __name__ == "__main__":
    main()
