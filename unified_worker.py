import os
import json
import logging
import pika
import time
import threading
from dotenv import load_dotenv
import boto3
import tempfile
from utils.sshagent import SSHAgent
from utils.certbot import request_certificate
from utils.s3 import upload_cert_to_s3

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("cert-unified-worker")

# RabbitMQ configuration
RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", 5672))
RABBITMQ_USER = os.environ.get("RABBITMQ_DEFAULT_USER", "user")
RABBITMQ_PASS = os.environ.get("RABBITMQ_DEFAULT_PASS", "password")
QUEUE_NAME_REQUESTS = "cert_requests"
QUEUE_NAME_SUCCESS = "cert_success"

# Certificate request settings
DNS_PLUGIN = os.environ.get("CERTBOT_DNS_PLUGIN", "dns-route53")
CERTBOT_CONFIG_DIR = os.environ.get("CERTBOT_CONFIG_DIR", "/etc/certbot")
CERTBOT_LOG_DIR = os.environ.get("CERTBOT_LOG_DIR", "/var/log/certbot")
ACME_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
RETRY_DELAY_MS = 60000  # 60 seconds in milliseconds
MAX_RETRY_COUNT = 5  # Maximum number of retries

# SSH and S3 configuration for deployment
SSH_HOST = os.environ.get("SSH_HOST", "172.31.35.222")
SSH_PORT = int(os.environ.get("SSH_PORT", 22))
SSH_USER = os.environ.get("SSH_USER", "ubuntu")
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/root/.ssh/key.pem")
S3_CERT_BUCKET = os.environ.get("S3_CERT_BUCKET", "accesstrade-server-configs")

def setup_delay_queue(channel, queue_name):
    """
    Set up the queues and exchanges needed for delayed message processing
    """
    # Create the retry exchange
    retry_exchange_name = f"{queue_name}_retry_exchange"
    channel.exchange_declare(
        exchange=retry_exchange_name,
        exchange_type='direct',
        durable=True
    )
    
    # Create the delay queue with the specified TTL (time-to-live)
    delay_queue_name = f"{queue_name}_delay_queue"
    arguments = {
        'x-dead-letter-exchange': '',  # Default exchange
        'x-dead-letter-routing-key': queue_name,  # Route back to the original queue
        'x-message-ttl': RETRY_DELAY_MS,  # Delay time in milliseconds
    }
    channel.queue_declare(
        queue=delay_queue_name,
        durable=True,
        arguments=arguments
    )
    
    # Bind the delay queue to the retry exchange
    channel.queue_bind(
        queue=delay_queue_name,
        exchange=retry_exchange_name,
        routing_key=delay_queue_name
    )
    
    logger.info(f"Configured delay queue: {delay_queue_name} with TTL: {RETRY_DELAY_MS}ms")
    return retry_exchange_name, delay_queue_name

def process_cert_request(body, channel=None):
    try:
        data = json.loads(body)
        logger.info(f"Received certificate request: {data}")
        domain = data.get("domain")
        email = data.get("email")
        if not domain or not email:
            logger.error("Missing domain or email in request")
            return False
        
        logger.info(f"Processing certificate request for {domain} with email {email}")

        # Request certificate using the utility function
        if request_certificate(
            domain, 
            email, 
            dns_plugin=DNS_PLUGIN,
            config_dir=CERTBOT_CONFIG_DIR,
            log_dir=CERTBOT_LOG_DIR
        ):
            # Publish success event to RabbitMQ
            if channel:
                channel.basic_publish(
                    exchange='',
                    routing_key=QUEUE_NAME_SUCCESS,
                    body=json.dumps({"domain": domain, "status": "success"}),
                    properties=pika.BasicProperties(delivery_mode=2)
                )
                logger.info(f"Published success event for {domain}")
            else:
                logger.warning("No channel provided, couldn't publish success event")
            return True
        else:
            logger.error(f"Certificate request failed for {domain}")
            return False
    except Exception as e:
        logger.error(f"Failed to process cert request message: {e}")
        return False

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
    """Main function to handle both certificate requests and success events."""
    # Connect to RabbitMQ
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    parameters = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=credentials
    )
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    
    # Declare both queues
    channel.queue_declare(queue=QUEUE_NAME_REQUESTS, durable=True)
    channel.queue_declare(queue=QUEUE_NAME_SUCCESS, durable=True)
    
    # Set up the delay mechanism for requests
    retry_exchange, delay_queue = setup_delay_queue(channel, QUEUE_NAME_REQUESTS)
    
    # Define callback for certificate requests
    def request_callback(ch, method, properties, body):
        # Extract retry count from message headers or set to 0 if not present
        headers = properties.headers or {}
        retry_count = headers.get('x-retry-count', 0)
        
        if process_cert_request(body, ch):
            # Only acknowledge the message if processing was successful
            ch.basic_ack(delivery_tag=method.delivery_tag)
        else:
            # If processing failed, check if we should retry
            if retry_count < MAX_RETRY_COUNT:
                logger.warning(f"Certificate request processing failed, retry {retry_count + 1}/{MAX_RETRY_COUNT} in {RETRY_DELAY_MS/1000} seconds")
                
                # Update headers with increased retry count
                new_headers = headers.copy() if headers else {}
                new_headers['x-retry-count'] = retry_count + 1
                
                # Publish to the retry exchange which will route to the delay queue
                ch.basic_publish(
                    exchange=retry_exchange,
                    routing_key=delay_queue,
                    body=body,
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # make message persistent
                        headers=new_headers
                    )
                )
                # Acknowledge the original message since we've re-queued it
                ch.basic_ack(delivery_tag=method.delivery_tag)
            else:
                logger.error(f"Certificate request failed after {MAX_RETRY_COUNT} attempts, giving up")
                # Either move to a dead-letter queue for failed messages or just acknowledge
                # Here we acknowledge to remove from the queue
                ch.basic_ack(delivery_tag=method.delivery_tag)
    
    # Define callback for success events
    def success_callback(ch, method, properties, body):
        if process_success_event(body):
            ch.basic_ack(delivery_tag=method.delivery_tag)
        else:
            # For success events, if processing fails, we don't want to retry forever
            logger.warning("Failed to process success event, acknowledging anyway")
            ch.basic_ack(delivery_tag=method.delivery_tag)
    
    # Set quality of service and consume from both queues
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME_REQUESTS, on_message_callback=request_callback)
    channel.basic_consume(queue=QUEUE_NAME_SUCCESS, on_message_callback=success_callback)
    
    logger.info(f"Unified worker started. Listening for messages on queues '{QUEUE_NAME_REQUESTS}' and '{QUEUE_NAME_SUCCESS}'. To exit press CTRL+C")
    
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    finally:
        connection.close()

if __name__ == "__main__":
    main()
