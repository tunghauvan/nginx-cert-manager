import os
import json
import logging
import pika
from dotenv import load_dotenv
import boto3

import subprocess
import tempfile
import time
import threading

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("cert-request-worker")

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", 5672))
RABBITMQ_USER = os.environ.get("RABBITMQ_DEFAULT_USER", "user")
RABBITMQ_PASS = os.environ.get("RABBITMQ_DEFAULT_PASS", "password")
QUEUE_NAME = "cert_requests"
QUEUE_NAME_SUCCESS = "cert_success"

# Use this environment variable to specify the DNS plugin
DNS_PLUGIN = os.environ.get("CERTBOT_DNS_PLUGIN", "dns-route53")
# Directory to store certbot configuration and credentials
CERTBOT_CONFIG_DIR = os.environ.get("CERTBOT_CONFIG_DIR", "/etc/certbot")
# Directory to store certbot logs
CERTBOT_LOG_DIR = os.environ.get("CERTBOT_LOG_DIR", "/var/log/certbot")

ACME_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"  # Use staging for testing
# Set up delay queue configuration
RETRY_DELAY_MS = 60000  # 60 seconds in milliseconds
MAX_RETRY_COUNT = 5  # Maximum number of retries

def setup_delay_queue(channel):
    """
    Set up the queues and exchanges needed for delayed message processing
    Based on: https://medium.com/@eran.amrani/re-routing-messages-with-delay-in-rabbitmq-4a52185f5098
    """
    # Create the retry exchange
    retry_exchange_name = f"{QUEUE_NAME}_retry_exchange"
    channel.exchange_declare(
        exchange=retry_exchange_name,
        exchange_type='direct',
        durable=True
    )
    
    # Create the delay queue with the specified TTL (time-to-live)
    delay_queue_name = f"{QUEUE_NAME}_delay_queue"
    arguments = {
        'x-dead-letter-exchange': '',  # Default exchange
        'x-dead-letter-routing-key': QUEUE_NAME,  # Route back to the original queue
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

def upload_cert_to_s3(domain, cert_dir):
    """Upload certificate files to S3 bucket"""
    try:
        s3_bucket = "accesstrade-server-configs"
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

def request_certificate(domain, email):
    """
    Request a certificate using Certbot with DNS challenge.
    """
    logger.info(f"Requesting certificate for {domain} using Certbot with DNS challenge")
    try:
        return True  # Placeholder for actual certificate request logic
        # Ensure output directories exist
        cert_dir = os.environ.get("CERT_OUTPUT_DIR", "/etc/nginx/ssl")
        os.makedirs(cert_dir, exist_ok=True)
        os.makedirs(CERTBOT_CONFIG_DIR, exist_ok=True)
        os.makedirs(CERTBOT_LOG_DIR, exist_ok=True)
        
        # Build the certbot command
        cmd = [
            "certbot", "certonly", "--non-interactive",
            "--agree-tos", "--email", email,
            "--preferred-challenges", "dns",
            f"--{DNS_PLUGIN}",
            "-d", domain,
            "--cert-name", domain.replace(".", "-"),
            "--config-dir", CERTBOT_CONFIG_DIR,
            "--logs-dir", CERTBOT_LOG_DIR,
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
            CERTBOT_CONFIG_DIR, "live", domain.replace(".", "-"), "fullchain.pem"
        )
        key_path = os.path.join(
            CERTBOT_CONFIG_DIR, "live", domain.replace(".", "-"), "privkey.pem"
        )
        chain_path = os.path.join(
            CERTBOT_CONFIG_DIR, "live", domain.replace(".", "-"), "chain.pem"
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

def process_cert_request(body, ch=None, method=None):
    try:
        data = json.loads(body)
        logger.info(f"Received certificate request: {data}")
        domain = data.get("domain")
        email = data.get("email")
        if not domain or not email:
            logger.error("Missing domain or email in request")
            return False
        
        logger.info(f"Processing certificate request for {domain} with email {email}")

        # Request certificate (blocking)
        if request_certificate(domain, email):
            # Publish success event to RabbitMQ
            credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
            parameters = pika.ConnectionParameters(
                host=RABBITMQ_HOST,
                port=RABBITMQ_PORT,
                credentials=credentials
            )
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            queue_name = QUEUE_NAME_SUCCESS
            channel.queue_declare(queue=queue_name, durable=True)
            channel.basic_publish(
                exchange='',
                routing_key=queue_name,
                body=json.dumps({"domain": domain, "status": "success"}),
                properties=pika.BasicProperties(delivery_mode=2)
            )
            connection.close()
            logger.info(f"Published success event for {domain}")
            
            # Don't wait for success event, that's handled by another worker
            return True
        else:
            logger.error(f"Certificate request failed for {domain}")
            return False
    except Exception as e:
        logger.error(f"Failed to process message: {e}")
        return False

def main():
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    parameters = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=credentials
    )
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    
    # Set up the delay mechanism
    retry_exchange, delay_queue = setup_delay_queue(channel)
    
    def callback(ch, method, properties, body):
        # Extract retry count from message headers or set to 0 if not present
        headers = properties.headers or {}
        retry_count = headers.get('x-retry-count', 0)
        
        if process_cert_request(body, ch, method):
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

    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)

    logger.info(f"Waiting for messages in queue '{QUEUE_NAME}'. To exit press CTRL+C")
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    finally:
        connection.close()

if __name__ == "__main__":
    main()
