import os
import json
import logging
import pika
import time
import threading
from datetime import datetime, timezone # Added timezone
from dotenv import load_dotenv
import boto3
import tempfile
from utils.sshagent import SSHAgent
from utils.certbot import request_certificate
from utils.s3 import upload_cert_to_s3
from utils.rabbitmq import setup_delay_queue # Import from utils
from utils.k8s_utils import update_crd_status # Import from renamed utils file
from kubernetes import client, config
from kubernetes.client.rest import ApiException

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
QUEUE_NAME_DEPLOYMENT = "cert_deployments"
QUEUE_NAME_DEPLOYMENT_SUCCESS = "cert_deployments_success" # New success queue
QUEUE_NAME_DEPLOYMENT_DLQ = "cert_deployments_dlq"       # New DLQ queue

# Certificate request settings
DNS_PLUGIN = os.environ.get("CERTBOT_DNS_PLUGIN", "dns-route53")
CERTBOT_CONFIG_DIR = os.environ.get("CERTBOT_CONFIG_DIR", "/etc/certbot")
CERTBOT_LOG_DIR = os.environ.get("CERTBOT_LOG_DIR", "/var/log/certbot")
ACME_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
RETRY_DELAY_MS = 60000  # 60 seconds in milliseconds
MAX_RETRY_COUNT = 3  # Maximum number of retries

# SSH and S3 configuration for deployment
# SSH_HOST = os.environ.get("SSH_HOST", "172.31.35.222") # No longer primary source for host
SSH_PORT = int(os.environ.get("SSH_PORT", 22))
SSH_USER = os.environ.get("SSH_USER", "ubuntu")
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/root/.ssh/key.pem")
S3_CERT_BUCKET = os.environ.get("S3_CERT_BUCKET", "accesstrade-server-configs")

# Kubernetes CRD settings
CRD_GROUP = "cert.nginx.io"
CRD_VERSION = "v1"
CRD_PLURAL = "domaincertificates"

# Initialize Kubernetes client
k8s_custom_objects_api = None
try:
    # Try in-cluster configuration first
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        config.load_incluster_config()
        logger.info("Using in-cluster Kubernetes configuration")
    else:
        # Fall back to local kubeconfig
        config.load_kube_config()
        logger.info("Using local Kubernetes configuration")
        
    k8s_custom_objects_api = client.CustomObjectsApi()
    logger.info("Kubernetes client initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize Kubernetes client: {e}")
    logger.warning("CRD status updates will be disabled")

def process_cert_request(body, channel=None):
    instance_ip = None # Variable to store instance IP
    crd_name = None
    crd_namespace = "default"
    try:
        data = json.loads(body)
        logger.info(f"Received certificate request: {data}")

        # Extract basic information
        domain = data.get("domain")
        email = data.get("email")

        # Extract CRD information for status updates and fetching spec
        crd_name = data.get("crd_name")
        crd_namespace = data.get("crd_namespace", "default")

        if not domain or not email:
            logger.error("Missing domain or email in request")
            if crd_name:
                update_crd_status( # Call imported function
                    k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                    crd_namespace, crd_name, {
                    "state": "Error",
                    "message": "Missing domain or email in request",
                    "conditions": [{
                        "type": "Ready",
                        "status": "False",
                        "reason": "InvalidRequest",
                        "message": "Missing domain or email in request",
                        "lastTransitionTime": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    }]
                }, logger)
            return False

        logger.info(f"Processing certificate request for {domain} with email {email}")

        # Fetch the CR to get instanceIp if k8s client is available
        if crd_name and k8s_custom_objects_api:
            try:
                cr_object = k8s_custom_objects_api.get_namespaced_custom_object(
                    group=CRD_GROUP,
                    version=CRD_VERSION,
                    namespace=crd_namespace,
                    plural=CRD_PLURAL,
                    name=crd_name
                )
                # Extract instanceIp from the first nginxConfig entry (adjust if needed)
                nginx_configs = cr_object.get('spec', {}).get('nginxConfigs', [])
                if nginx_configs and isinstance(nginx_configs, list) and len(nginx_configs) > 0:
                    instance_ip = nginx_configs[0].get('instanceIp')
                    if not instance_ip:
                         logger.warning(f"CR {crd_namespace}/{crd_name} found, but 'instanceIp' is missing in the first nginxConfigs entry.")
                else:
                    logger.warning(f"CR {crd_namespace}/{crd_name} found, but 'nginxConfigs' array is missing, empty, or not a list.")

            except ApiException as e:
                logger.error(f"Failed to fetch CR {crd_namespace}/{crd_name} to get instanceIp: {e}")
                # Decide if this is a fatal error for the request processing
                # For now, we'll log and continue, deployment might fail later if IP is needed
            except Exception as e:
                 logger.error(f"An unexpected error occurred while fetching CR {crd_namespace}/{crd_name}: {e}")


        # Update CRD status to Processing
        if crd_name:
            update_crd_status( # Call imported function
                k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                crd_namespace, crd_name, {
                "state": "Processing",
                "message": "Certificate request is being processed",
                "conditions": [{
                    "type": "Ready",
                    "status": "False",
                    "reason": "Processing",
                    "message": "Certificate request is being processed",
                    "lastTransitionTime": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                }]
            }, logger)

        # Request certificate
        if request_certificate(
            domain,
            email,
            dns_plugin=DNS_PLUGIN,
            config_dir=CERTBOT_CONFIG_DIR,
            log_dir=CERTBOT_LOG_DIR
        ):
            # Certificate successfully issued
            logger.info(f"Certificate issued successfully for {domain}")
            
            # Get certificate details (in a real implementation, parse from certificate)
            now = datetime.now(timezone.utc)
            not_before = now.strftime('%Y-%m-%dT%H:%M:%SZ')
            # Set expiry to 90 days (typical for Let's Encrypt)
            not_after = datetime(now.year + (1 if now.month <= 9 else 0), 
                                 ((now.month + 3 - 1) % 12) + 1, 
                                 min(now.day, 28)).strftime('%Y-%m-%dT%H:%M:%SZ')
            serial_number = f"mock-{int(time.time())}"  # Real implementation would get actual serial number
            
            # Update CRD status to Issued with certificate details
            if crd_name:
                update_crd_status( # Call imported function
                    k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                    crd_namespace, crd_name, {
                    "state": "Issued",
                    "message": "Certificate issued successfully",
                    "notBefore": not_before,
                    "notAfter": not_after,
                    "serialNumber": serial_number,
                    "conditions": [{
                        "type": "Ready",
                        "status": "True",
                        "reason": "CertificateIssued",
                        "message": "Certificate successfully issued",
                        "lastTransitionTime": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    }]
                }, logger)

            # Publish success event to RabbitMQ with CRD information AND instanceIp
            if channel:
                deployment_payload = {
                    "domain": domain,
                    "status": "success",
                    "crd_name": crd_name,
                    "crd_namespace": crd_namespace
                }
                if instance_ip: # Only include instance_ip if found
                    deployment_payload["instanceIp"] = instance_ip
                else:
                    logger.warning(f"Instance IP not found for {domain}, deployment message will not include it.")

                channel.basic_publish(
                    exchange='',
                    routing_key=QUEUE_NAME_DEPLOYMENT,
                    body=json.dumps(deployment_payload),
                    properties=pika.BasicProperties(delivery_mode=2)
                )
                logger.info(f"Published success event for {domain} with payload: {deployment_payload}")
            else:
                logger.warning("No channel provided, couldn't publish success event")

            return True
        else:
            # Certificate request failed
            logger.error(f"Certificate request failed for {domain}")

            # Update CRD status to Error
            if crd_name:
                update_crd_status( # Call imported function
                    k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                    crd_namespace, crd_name, {
                    "state": "Error",
                    "message": "Failed to issue certificate",
                    "conditions": [{
                        "type": "Ready",
                        "status": "False",
                        "reason": "IssueFailed",
                        "message": "Failed to issue certificate",
                        "lastTransitionTime": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    }]
                }, logger)
            return False
    except Exception as e:
        logger.error(f"Failed to process cert request message: {e}")
        # Update CRD status to Error if we have CRD information
        try:
            # Use crd_name and crd_namespace captured at the beginning of the try block
            if crd_name:
                update_crd_status( # Call imported function
                    k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                    crd_namespace, crd_name, {
                    "state": "Error",
                    "message": f"Error processing certificate request: {str(e)}",
                    "conditions": [{
                        "type": "Ready",
                        "status": "False",
                        "reason": "ProcessingError",
                        "message": f"Error processing certificate request: {str(e)}",
                        "lastTransitionTime": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    }]
                }, logger)
        except Exception as update_error:
            logger.error(f"Failed to update CRD status after error: {update_error}")
        return False

def process_deployment_event(body, channel): # Added channel parameter
    """Process a certificate success event."""
    domain = None
    crd_name = None
    crd_namespace = "default"
    instance_ip = None # Variable for instance IP - will be fetched from CR
    deployment_successful = False # Flag to track success

    try:
        data = json.loads(body)
        domain = data.get("domain")
        status = data.get("status")
        crd_name = data.get("crd_name")
        crd_namespace = data.get("crd_namespace", "default")
        # instance_ip = data.get("instanceIp") # REMOVED: Get instance IP from message

        if not domain or status != "success" or not crd_name: # Added check for crd_name
            logger.error(f"Invalid success event data (missing domain, crd_name, or status not 'success'): {data}")
            # Publish to DLQ even for invalid data
            channel.basic_publish(
                exchange='',
                routing_key=QUEUE_NAME_DEPLOYMENT_DLQ,
                body=body,
                properties=pika.BasicProperties(delivery_mode=2)
            )
            logger.info(f"Published invalid event for domain {domain or 'Unknown'} to DLQ")
            # Try to update CRD status if possible, though unlikely with missing info
            if crd_name:
                 update_crd_status(
                     k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                     crd_namespace, crd_name, {
                     "state": "Error",
                     "message": "Deployment failed: Invalid deployment event data received."
                 }, logger)
            return False # Indicate failure

        # Fetch the CR to get instanceIp if k8s client is available
        if k8s_custom_objects_api:
            try:
                logger.info(f"Fetching CR {crd_namespace}/{crd_name} to get instanceIp for deployment.")
                cr_object = k8s_custom_objects_api.get_namespaced_custom_object(
                    group=CRD_GROUP,
                    version=CRD_VERSION,
                    namespace=crd_namespace,
                    plural=CRD_PLURAL,
                    name=crd_name
                )
                # Extract instanceIp from the first nginxConfig entry (adjust if needed)
                nginx_configs = cr_object.get('spec', {}).get('nginxConfigs', [])
                if nginx_configs and isinstance(nginx_configs, list) and len(nginx_configs) > 0:
                    instance_ip = nginx_configs[0].get('instanceIp')
                    if not instance_ip:
                         logger.error(f"CR {crd_namespace}/{crd_name} found, but 'instanceIp' is missing in the first nginxConfigs entry.")
                         # Publish to DLQ because we can't connect without IP
                         channel.basic_publish(exchange='', routing_key=QUEUE_NAME_DEPLOYMENT_DLQ, body=body, properties=pika.BasicProperties(delivery_mode=2))
                         logger.info(f"Published failed deployment event for {domain} to DLQ due to missing instanceIp in CR.")
                         update_crd_status(
                             k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                             crd_namespace, crd_name, {
                             "state": "Error",
                             "message": "Deployment failed: Missing 'instanceIp' in CR spec.nginxConfigs."
                         }, logger)
                         return False # Indicate failure
                    else:
                        logger.info(f"Found instanceIp '{instance_ip}' in CR {crd_namespace}/{crd_name}.")
                else:
                    logger.error(f"CR {crd_namespace}/{crd_name} found, but 'nginxConfigs' array is missing, empty, or not a list.")
                    # Publish to DLQ
                    channel.basic_publish(exchange='', routing_key=QUEUE_NAME_DEPLOYMENT_DLQ, body=body, properties=pika.BasicProperties(delivery_mode=2))
                    logger.info(f"Published failed deployment event for {domain} to DLQ due to missing nginxConfigs in CR.")
                    update_crd_status(
                        k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                        crd_namespace, crd_name, {
                        "state": "Error",
                        "message": "Deployment failed: Missing 'nginxConfigs' array in CR spec."
                    }, logger)
                    return False # Indicate failure

            except ApiException as e:
                logger.error(f"Failed to fetch CR {crd_namespace}/{crd_name} to get instanceIp: {e.status} - {e.reason}")
                # Publish to DLQ
                channel.basic_publish(exchange='', routing_key=QUEUE_NAME_DEPLOYMENT_DLQ, body=body, properties=pika.BasicProperties(delivery_mode=2))
                logger.info(f"Published failed deployment event for {domain} to DLQ due to K8s API error fetching CR.")
                update_crd_status(
                    k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                    crd_namespace, crd_name, {
                    "state": "Error",
                    "message": f"Deployment failed: Could not fetch CR details ({e.status} - {e.reason})."
                }, logger)
                return False # Indicate failure
            except Exception as e:
                 logger.error(f"An unexpected error occurred while fetching CR {crd_namespace}/{crd_name}: {e}")
                 # Publish to DLQ
                 channel.basic_publish(exchange='', routing_key=QUEUE_NAME_DEPLOYMENT_DLQ, body=body, properties=pika.BasicProperties(delivery_mode=2))
                 logger.info(f"Published failed deployment event for {domain} to DLQ due to unexpected error fetching CR.")
                 update_crd_status(
                     k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                     crd_namespace, crd_name, {
                     "state": "Error",
                     "message": f"Deployment failed: Unexpected error fetching CR details: {str(e)}."
                 }, logger)
                 return False # Indicate failure
        else:
            # Kubernetes client not available - cannot proceed with deployment if IP wasn't somehow passed (which it isn't anymore)
            logger.error("Kubernetes client not available. Cannot fetch instanceIp from CR to proceed with deployment.")
            # Publish to DLQ
            channel.basic_publish(exchange='', routing_key=QUEUE_NAME_DEPLOYMENT_DLQ, body=body, properties=pika.BasicProperties(delivery_mode=2))
            logger.info(f"Published failed deployment event for {domain} to DLQ due to unavailable K8s client.")
            # Cannot update CRD status without the client
            return False # Indicate failure


        # Removed the check for instance_ip here as it's handled during CR fetching above.
        # if not instance_ip: ...

        logger.info(f"Processing success event for domain: {domain}, deploying to instance: {instance_ip}")

        # Update CRD status to Deploying if available (k8s_client check is implicitly done above)
        update_crd_status( # Call imported function
            k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
            crd_namespace, crd_name, {
            "state": "Deploying",
            "message": f"Certificate is being deployed to NGINX server at {instance_ip}"
        }, logger)

        # Initialize SSH connection to deploy certificate
        ssh = SSHAgent()
        try:
            target_key_filename = os.getenv("TARGET_KEY_FILENAME", SSH_KEY_PATH) # Use SSH_KEY_PATH as default if not set
            target_port_str = os.getenv("TARGET_PORT", "22")
            jump_hostname = os.getenv("JUMP_HOSTNAME")
            jump_username = os.getenv("JUMP_USERNAME")
            jump_key_filename = os.getenv("JUMP_KEY_FILENAME") # Optional: Key for jump host itself
            jump_passphrase = os.getenv("JUMP_PASSPHRASE") # Optional: Passphrase for jump host key or target key if on jump host
            jump_port_str = os.getenv("JUMP_PORT", "22")
            target_key_on_jump_host_str = os.getenv("TARGET_KEY_ON_JUMP_HOST", "False").lower()
            target_key_on_jump_host = target_key_on_jump_host_str == 'true'

            try:
                target_port = int(target_port_str)
                jump_port = int(jump_port_str)
            except ValueError:
                print("Error: TARGET_PORT or JUMP_PORT environment variable is not a valid integer.")
                exit(1)

            # Connect to remote server using instance_ip
            logger.info(f"Attempting SSH connection to {instance_ip}:{SSH_PORT} as user {SSH_USER}")
            connection = ssh.connect(
                hostname=instance_ip, # Use instance_ip here
                port=SSH_PORT,
                username=SSH_USER,
                key_filename=target_key_filename, # Path to target key (potentially on jump host)
                jump_hostname=jump_hostname,
                jump_port=jump_port,
                jump_username=jump_username,
                jump_key_filename=jump_key_filename, # Key for jump host authentication
                jump_passphrase=jump_passphrase, # Passphrase for jump host key (or target key if on jump host and encrypted)
                target_key_on_jump_host=target_key_on_jump_host
            )

            if not connection:
                logger.error(f"Failed to connect to SSH server {instance_ip}")
                # Publish to DLQ on SSH connection failure
                channel.basic_publish(
                    exchange='',
                    routing_key=QUEUE_NAME_DEPLOYMENT_DLQ,
                    body=body,
                    properties=pika.BasicProperties(delivery_mode=2)
                )
                logger.info(f"Published failed deployment event for {domain} to DLQ due to SSH connection error to {instance_ip}")
                # Update CRD status if possible
                if crd_name:
                    update_crd_status( # Call imported function
                        k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                        crd_namespace, crd_name, {
                        "state": "Error",
                        "message": f"Deployment failed: Could not connect to SSH server {instance_ip}"
                    }, logger)
                return False # Indicate failure

            # Create certificate directory if it doesn't exist
            target_dir = f"/etc/letsencrypt/live/{domain}"
            command = f"sudo mkdir -p {target_dir}"
            exit_code, stdout, stderr = ssh.execute_command(command)

            if exit_code != 0:
                logger.error(f"Failed to create directory {target_dir} on {instance_ip}: {stderr}")
                # Consider publishing to DLQ and updating status here as well
                return False # Indicate failure

            # Upload the certificate files
            # Fullchain certificate
            s3_cert_path = f"s3://{S3_CERT_BUCKET}/certs/{domain}/{domain}.crt"
            temp_remote_path = f"/tmp/fullchain.pem"
            final_remote_path = f"{target_dir}/fullchain.pem"

            if not ssh.upload_from_s3_to_remote(s3_cert_path, temp_remote_path):
                logger.error(f"Certificate upload failed for {domain} to {instance_ip}")
                # Consider publishing to DLQ and updating status
                return False

            logger.info(f"Certificate uploaded to temporary location {temp_remote_path} on {instance_ip}")

            # Move the certificate file to the final destination with sudo and set permissions
            move_command = f"sudo cp {temp_remote_path} {final_remote_path} && sudo chmod 644 {final_remote_path} && rm {temp_remote_path}"
            exit_code, stdout, stderr = ssh.execute_command(move_command)

            if exit_code != 0:
                logger.error(f"Failed to move certificate to final destination on {instance_ip}: {stderr}")
                # Consider publishing to DLQ and updating status
                return False

            logger.info(f"Certificate successfully deployed to {final_remote_path} on {instance_ip}")

            # Process the private key file
            s3_key_path = f"s3://{S3_CERT_BUCKET}/certs/{domain}/{domain}.key"
            temp_key_path = f"/tmp/privkey.pem"
            final_key_path = f"{target_dir}/privkey.pem"

            if not ssh.upload_from_s3_to_remote(s3_key_path, temp_key_path):
                logger.error(f"Private key upload failed for {domain} to {instance_ip}")
                # Consider publishing to DLQ and updating status
                return False

            logger.info(f"Private key uploaded to temporary location {temp_key_path} on {instance_ip}")

            # Move the key file to the final destination with sudo and set more restrictive permissions
            move_key_command = f"sudo cp {temp_key_path} {final_key_path} && sudo chmod 600 {final_key_path} && rm {temp_key_path}"
            exit_code, stdout, stderr = ssh.execute_command(move_key_command)

            if exit_code != 0:
                logger.error(f"Failed to move private key to final destination on {instance_ip}: {stderr}")
                # Consider publishing to DLQ and updating status
                return False

            logger.info(f"Private key successfully deployed to {final_key_path} on {instance_ip}")

            # Reload Nginx or other web server if needed
            reload_command = "sudo systemctl reload nginx"
            exit_code, stdout, stderr = ssh.execute_command(reload_command)
            if exit_code != 0:
                logger.warning(f"Failed to reload nginx on {instance_ip}: {stderr}")
                # Decide if this is critical. For now, let's consider deployment successful even if reload fails.
            else:
                logger.info(f"Nginx reloaded successfully on {instance_ip}")


            logger.info(f"Success event for {domain} processed completely for instance {instance_ip}")
            deployment_successful = True # Mark deployment as successful

            # Update CRD status to Deployed, including deployedTo list
            if crd_name and k8s_custom_objects_api:
                deployed_to_list = []
                try:
                    # Fetch current CR to get existing deployedTo list
                    current_cr = k8s_custom_objects_api.get_namespaced_custom_object(
                        group=CRD_GROUP,
                        version=CRD_VERSION,
                        namespace=crd_namespace,
                        plural=CRD_PLURAL,
                        name=crd_name
                    )
                    deployed_to_list = current_cr.get('status', {}).get('deployedTo', [])
                    if not isinstance(deployed_to_list, list): # Ensure it's a list
                        logger.warning(f"Existing status.deployedTo for {crd_namespace}/{crd_name} is not a list. Resetting.")
                        deployed_to_list = []

                except ApiException as e:
                    logger.warning(f"Failed to fetch current CR status for {crd_namespace}/{crd_name} before updating deployedTo: {e}. Proceeding without existing list.")
                except Exception as e:
                    logger.warning(f"Unexpected error fetching current CR status for {crd_namespace}/{crd_name}: {e}. Proceeding without existing list.")


                # Create new entry for this deployment
                deploy_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                new_deployment_entry = {
                    "server": instance_ip, # Use instance_ip as the server identifier
                    "deployTime": deploy_time,
                    "status": "Success"
                }

                # Optional: Remove previous entries for the same server to keep only the latest
                deployed_to_list = [entry for entry in deployed_to_list if entry.get('server') != instance_ip]
                deployed_to_list.append(new_deployment_entry)

                # Prepare the full status update payload
                status_payload = {
                    "state": "Deployed",
                    "message": f"Certificate successfully deployed to NGINX server at {instance_ip}",
                    "deployedTo": deployed_to_list, # Include the updated list
                    "conditions": [{
                        "type": "Ready",
                        "status": "True",
                        "reason": "CertificateDeployed",
                        "message": f"Certificate successfully deployed to {instance_ip}" # More specific message
                        # lastTransitionTime will be added by update_crd_status
                    }]
                }
                update_crd_status( # Call imported function
                    k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                    crd_namespace, crd_name, status_payload, logger)
            elif crd_name:
                 # Fallback if k8s client isn't available but we have crd_name (shouldn't happen often)
                 logger.warning("Kubernetes client not available, cannot update deployedTo status.")
                 update_crd_status( # Call imported function with basic status
                    k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                    crd_namespace, crd_name, {
                        "state": "Deployed",
                        "message": f"Certificate successfully deployed to NGINX server at {instance_ip}",
                         "conditions": [{
                            "type": "Ready",
                            "status": "True",
                            "reason": "CertificateDeployed",
                            "message": f"Certificate successfully deployed to {instance_ip}"
                        }]
                    }, logger)


            # Publish to success queue
            channel.basic_publish(
                exchange='',
                routing_key=QUEUE_NAME_DEPLOYMENT_SUCCESS,
                body=body, # Forward the original message body
                properties=pika.BasicProperties(delivery_mode=2)
            )
            logger.info(f"Published successful deployment event for {domain} to {QUEUE_NAME_DEPLOYMENT_SUCCESS}")
            return True # Indicate success

        except Exception as ssh_error: # Catch specific SSH/deployment errors
             logger.error(f"Error during SSH deployment for {domain} to {instance_ip}: {ssh_error}")
             # Publish to DLQ on specific deployment errors
             channel.basic_publish(
                 exchange='',
                 routing_key=QUEUE_NAME_DEPLOYMENT_DLQ,
                 body=body,
                 properties=pika.BasicProperties(delivery_mode=2)
             )
             logger.info(f"Published failed deployment event for {domain} to DLQ due to deployment error on {instance_ip}: {ssh_error}")
             # Update CRD status to Error if possible (k8s_client check implicitly done above)
             # Prepare status update payload for error
             error_status_payload = {
                 "state": "Error",
                 "message": f"Deployment failed on {instance_ip}: {str(ssh_error)}"
                 # Optionally add/update a 'Deployed' condition with status False
             }
             # Add deployedTo status for the failure attempt
             deployed_to_list = []
             try:
                 current_cr = k8s_custom_objects_api.get_namespaced_custom_object(
                     group=CRD_GROUP, version=CRD_VERSION, namespace=crd_namespace, plural=CRD_PLURAL, name=crd_name
                 )
                 deployed_to_list = current_cr.get('status', {}).get('deployedTo', [])
                 if not isinstance(deployed_to_list, list): deployed_to_list = []
             except Exception: pass # Ignore errors fetching status during error handling

             deploy_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
             failed_deployment_entry = {
                 "server": instance_ip,
                 "deployTime": deploy_time,
                 "status": "Failed",
                 "error": str(ssh_error) # Add error message
             }
             deployed_to_list = [entry for entry in deployed_to_list if entry.get('server') != instance_ip]
             deployed_to_list.append(failed_deployment_entry)
             error_status_payload["deployedTo"] = deployed_to_list

             update_crd_status( # Call imported function
                 k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                 crd_namespace, crd_name, error_status_payload, logger)

             return False # Indicate failure
        finally:
            # Ensure SSH connection is closed
            ssh.disconnect()
            # If deployment failed before reaching the success publish step, publish to DLQ here
            if not deployment_successful:
                 # Rely on specific error handling above to publish to DLQ.
                 pass


    except Exception as e:
        logger.error(f"Failed to process success event: {e}")
        # Publish to DLQ on general processing failure
        channel.basic_publish(
            exchange='',
            routing_key=QUEUE_NAME_DEPLOYMENT_DLQ,
            body=body,
            properties=pika.BasicProperties(delivery_mode=2)
        )
        logger.info(f"Published failed deployment event for {domain or 'Unknown'} to DLQ due to processing error: {e}")
        # Update CRD status to Error if possible
        if crd_name and domain and k8s_custom_objects_api: # Check if we have enough info and k8s client
             update_crd_status( # Call imported function
                 k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                 crd_namespace, crd_name, {
                 "state": "Error",
                 "message": f"Error processing deployment event: {str(e)}",
                 # "lastTransitionTime": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') # update_crd_status handles this
             }, logger)
        elif crd_name and domain:
            logger.warning("Cannot update CRD status after processing error because Kubernetes client is unavailable.")
        return False # Indicate failure

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
    channel.queue_declare(queue=QUEUE_NAME_DEPLOYMENT, durable=True)
    channel.queue_declare(queue=QUEUE_NAME_DEPLOYMENT_SUCCESS, durable=True) # Declare success queue
    channel.queue_declare(queue=QUEUE_NAME_DEPLOYMENT_DLQ, durable=True)     # Declare DLQ queue
    
    # Set up the delay mechanism for requests using the imported function
    retry_exchange, delay_queue = setup_delay_queue(channel, QUEUE_NAME_REQUESTS, RETRY_DELAY_MS, logger)
    
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
        # Process the event (which now handles publishing to success/DLQ)
        process_deployment_event(body, ch) # Pass channel 'ch'

        # Always acknowledge the message from the original QUEUE_NAME_DEPLOYMENT queue
        # as it has been processed (and potentially forwarded to success/DLQ).
        ch.basic_ack(delivery_tag=method.delivery_tag)
        logger.debug(f"Acknowledged message from {QUEUE_NAME_DEPLOYMENT}")


    # Set quality of service and consume from both queues
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME_REQUESTS, on_message_callback=request_callback)
    channel.basic_consume(queue=QUEUE_NAME_DEPLOYMENT, on_message_callback=success_callback)
    
    logger.info(f"Unified worker started. Listening for messages on queues '{QUEUE_NAME_REQUESTS}' and '{QUEUE_NAME_DEPLOYMENT}'. To exit press CTRL+C")
    
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    finally:
        connection.close()

if __name__ == "__main__":
    main()
