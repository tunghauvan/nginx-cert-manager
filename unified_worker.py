import os
import json
import logging
import pika
import time
import threading
import base64
from datetime import datetime, timezone, timedelta # Added timedelta
from dotenv import load_dotenv
import boto3
import tempfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
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
RENEWAL_CHECK_INTERVAL_SECONDS = 60 * 60 * 24 # Check once a day
RENEWAL_THRESHOLD_DAYS = 7 # Renew if expiring within 7 days
STUCK_STATE_TIMEOUT_SECONDS = 3600 # Reset stuck states after 1 hour (3600 seconds)

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
k8s_core_v1_api = None # Added CoreV1Api client
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
    k8s_core_v1_api = client.CoreV1Api() # Initialize CoreV1Api
    logger.info("Kubernetes clients (CustomObjectsApi, CoreV1Api) initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize Kubernetes clients: {e}")
    logger.warning("CRD status updates and renewal checks might be disabled or limited.")

def parse_certificate_expiry_from_s3(domain, s3_bucket=None):
    """
    Parse certificate from S3 and extract expiry information.
    
    Args:
        domain (str): The domain name for the certificate
        s3_bucket (str): Optional - S3 bucket name (defaults to env var)
        
    Returns:
        dict: Certificate details (notBefore, notAfter, serialNumber) or None if failed
    """
    try:
        s3_bucket = s3_bucket or os.environ.get("S3_CERT_BUCKET", "accesstrade-server-configs")
        s3_client = boto3.client('s3')
        
        # Download certificate
        cert_key = f"certs/{domain}/{domain}.crt"
        cert_response = s3_client.get_object(Bucket=s3_bucket, Key=cert_key)
        cert_data = cert_response['Body'].read()
        
        # Parse the certificate
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Extract certificate details
        not_before = cert.not_valid_before_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        not_after = cert.not_valid_after_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        serial_number = str(cert.serial_number)
        
        logger.debug(f"Certificate for {domain}: notBefore={not_before}, notAfter={not_after}, serial={serial_number}")
        
        return {
            'notBefore': not_before,
            'notAfter': not_after,
            'serialNumber': serial_number
        }
    except Exception as e:
        logger.error(f"Failed to parse certificate for {domain}: {e}")
        return None

def migrate_certificate_expiry_dates():
    """
    Migration function to fix incorrect expiry dates on startup.
    Reads actual expiry dates from S3 certificates and updates CRD status.
    """
    if not k8s_custom_objects_api or not k8s_core_v1_api:
        logger.warning("Kubernetes clients not available, skipping certificate expiry migration")
        return
    
    logger.info("=" * 80)
    logger.info("Starting certificate expiry date migration on startup")
    logger.info("=" * 80)
    
    success_count = 0
    failure_count = 0
    skipped_count = 0
    
    try:
        # List all namespaces
        namespaces = k8s_core_v1_api.list_namespace()
        logger.info(f"Found {len(namespaces.items)} namespaces to check")
        
        for ns in namespaces.items:
            namespace_name = ns.metadata.name
            
            try:
                # List all DomainCertificates in this namespace
                cr_list = k8s_custom_objects_api.list_namespaced_custom_object(
                    group=CRD_GROUP,
                    version=CRD_VERSION,
                    plural=CRD_PLURAL,
                    namespace=namespace_name
                )
                
                crs = cr_list.get('items', [])
                if not crs:
                    continue
                
                logger.info(f"Checking {len(crs)} DomainCertificates in namespace {namespace_name}")
                
                for cr in crs:
                    metadata = cr.get('metadata', {})
                    spec = cr.get('spec', {})
                    status = cr.get('status', {})
                    
                    name = metadata.get('name')
                    domain = spec.get('domain')
                    current_state = status.get('state')
                    current_not_after = status.get('notAfter')
                    
                    if not domain:
                        logger.debug(f"Skipping {namespace_name}/{name}: no domain in spec")
                        skipped_count += 1
                        continue
                    
                    # Only migrate if certificate is in Issued or Deployed state
                    if current_state not in ['Issued', 'Deployed']:
                        logger.debug(f"Skipping {namespace_name}/{name}: state is {current_state}")
                        skipped_count += 1
                        continue
                    
                    # Get actual certificate details from S3
                    cert_details = parse_certificate_expiry_from_s3(domain)
                    
                    if not cert_details:
                        logger.warning(f"Skipping {namespace_name}/{name}: could not parse certificate from S3")
                        skipped_count += 1
                        continue
                    
                    # Check if update is needed
                    if current_not_after == cert_details['notAfter']:
                        logger.debug(f"Skipping {namespace_name}/{name}: expiry date already correct")
                        skipped_count += 1
                        continue
                    
                    logger.info(f"Updating {namespace_name}/{name}: {current_not_after} -> {cert_details['notAfter']}")
                    
                    # Update CRD status with correct expiry dates
                    try:
                        # Update the status fields
                        status.update({
                            'notBefore': cert_details['notBefore'],
                            'notAfter': cert_details['notAfter'],
                            'serialNumber': cert_details['serialNumber']
                        })
                        
                        # Patch the status
                        k8s_custom_objects_api.patch_namespaced_custom_object_status(
                            group=CRD_GROUP,
                            version=CRD_VERSION,
                            namespace=namespace_name,
                            plural=CRD_PLURAL,
                            name=name,
                            body={'status': status}
                        )
                        
                        logger.info(f"Successfully updated {namespace_name}/{name}")
                        success_count += 1
                        
                    except ApiException as e:
                        logger.error(f"Failed to update {namespace_name}/{name}: {e.status} - {e.reason}")
                        failure_count += 1
                    except Exception as e:
                        logger.error(f"Unexpected error updating {namespace_name}/{name}: {e}")
                        failure_count += 1
                
            except ApiException as e:
                logger.error(f"Error listing DomainCertificates in namespace {namespace_name}: {e.status} - {e.reason}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error processing namespace {namespace_name}: {e}")
                continue
        
    except ApiException as e:
        logger.error(f"Error listing namespaces: {e.status} - {e.reason}")
    except Exception as e:
        logger.error(f"Unexpected error during migration: {e}")
    
    logger.info("=" * 80)
    logger.info("Certificate expiry date migration summary:")
    logger.info(f"  Successfully updated: {success_count}")
    logger.info(f"  Failed: {failure_count}")
    logger.info(f"  Skipped: {skipped_count}")
    logger.info("=" * 80)

def download_cert_from_s3(domain, s3_bucket=None):
    """
    Download certificate and key data from S3
    
    Args:
        domain (str): The domain name for the certificate
        s3_bucket (str): Optional - S3 bucket name (defaults to env var)
        
    Returns:
        tuple: (cert_data, key_data) or (None, None) if failed
    """
    try:
        s3_bucket = s3_bucket or os.environ.get("S3_CERT_BUCKET", "accesstrade-server-configs")
        s3_client = boto3.client('s3')
        
        # Download certificate
        cert_key = f"certs/{domain}/{domain}.crt"
        cert_response = s3_client.get_object(Bucket=s3_bucket, Key=cert_key)
        cert_data = cert_response['Body'].read().decode('utf-8')
        
        # Download private key
        key_key = f"certs/{domain}/{domain}.key"
        key_response = s3_client.get_object(Bucket=s3_bucket, Key=key_key)
        key_data = key_response['Body'].read().decode('utf-8')
        
        logger.info(f"Successfully downloaded certificate data for {domain} from S3")
        return cert_data, key_data
    except Exception as e:
        logger.error(f"Failed to download certificate data from S3: {e}")
        return None, None

def create_k8s_tls_secret(domain, cert_data, key_data, namespace="default"):
    """
    Create a Kubernetes TLS secret containing the certificate data
    
    Args:
        domain (str): The domain name for the certificate
        cert_data (str): PEM-encoded certificate data
        key_data (str): PEM-encoded private key data
        namespace (str): Kubernetes namespace
        
    Returns:
        bool: True if secret created successfully, False otherwise
    """
    if not k8s_core_v1_api:
        logger.warning("Kubernetes CoreV1Api client not available, cannot create TLS secret")
        return False
    
    try:
        # Create the secret name (sanitize domain name for Kubernetes)
        secret_name = f"tls-{domain.replace('.', '-')}"
        
        # Create the secret object
        secret = client.V1Secret(
            api_version="v1",
            kind="Secret",
            metadata=client.V1ObjectMeta(
                name=secret_name,
                namespace=namespace
            ),
            type="kubernetes.io/tls",
            data={
                "tls.crt": base64.b64encode(cert_data.encode('utf-8')).decode('utf-8'),
                "tls.key": base64.b64encode(key_data.encode('utf-8')).decode('utf-8')
            }
        )
        
        # Try to create the secret
        try:
            k8s_core_v1_api.create_namespaced_secret(namespace, secret)
            logger.info(f"Successfully created Kubernetes TLS secret '{secret_name}' in namespace '{namespace}'")
            return True
        except ApiException as e:
            if e.status == 409:  # Conflict - secret already exists
                # Update the existing secret
                k8s_core_v1_api.replace_namespaced_secret(secret_name, namespace, secret)
                logger.info(f"Successfully updated existing Kubernetes TLS secret '{secret_name}' in namespace '{namespace}'")
                return True
            else:
                logger.error(f"Failed to create/update Kubernetes TLS secret: {e}")
                return False
                
    except Exception as e:
        logger.error(f"Failed to create Kubernetes TLS secret: {e}")
        return False

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
        # action = data.get("action", "issue") # Optional: Distinguish between issue/renew if needed

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


        # Update CRD status to Processing (or Renewing if action=="renew")
        # The current update_crd_status logic might overwrite the state if called multiple times,
        # ensure the state reflects the current action.
        initial_state = "Processing" # Default state
        # If we explicitly track renewal, uncomment below
        # initial_state = "Renewing" if action == "renew" else "Processing"

        update_crd_status( # Call imported function
            k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
            crd_namespace, crd_name, {
            "state": initial_state,
            "message": f"Certificate {initial_state.lower()} started",
            "conditions": [{
                "type": "Ready",
                "status": "False",
                "reason": initial_state,
                "message": f"Certificate {initial_state.lower()} started",
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
            logger.info(f"Certificate issued/renewed successfully for {domain}")
            
            # Get certificate details (in a real implementation, parse from certificate)
            now = datetime.now(timezone.utc)
            not_before = now.strftime('%Y-%m-%dT%H:%M:%SZ')
            # Set expiry to 90 days (typical for Let's Encrypt)
            not_after = (now + timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
            serial_number = f"mock-{int(time.time())}"  # Real implementation would get actual serial number
            
            # Update CRD status to Issued with certificate details
            if crd_name:
                update_crd_status( # Call imported function
                    k8s_custom_objects_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                    crd_namespace, crd_name, {
                    "state": "Issued",
                    "message": "Certificate issued/renewed successfully",
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

            # Create Kubernetes TLS secret
            cert_data, key_data = download_cert_from_s3(domain)
            if cert_data and key_data:
                if create_k8s_tls_secret(domain, cert_data, key_data, crd_namespace):
                    logger.info(f"Successfully created/updated Kubernetes TLS secret for {domain}")
                else:
                    logger.warning(f"Failed to create Kubernetes TLS secret for {domain}")
            else:
                logger.warning(f"Could not download certificate data from S3 for {domain}, skipping TLS secret creation")

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

# --- Renewal Check Function ---
def check_and_trigger_renewals(channel, k8s_co_api, k8s_core_api, stop_event): # Added k8s_core_api parameter
    """Lists DomainCertificates per namespace, checks expiration, and triggers renewals."""
    logger.info("Starting periodic renewal check...")
    while not stop_event.is_set():
        try:
            if not k8s_co_api or not k8s_core_api: # Check both clients
                logger.warning("Kubernetes client(s) not available, skipping renewal check.")
                stop_event.wait(RENEWAL_CHECK_INTERVAL_SECONDS)
                continue

            logger.info("Listing namespaces for renewal check...")
            try:
                namespaces = k8s_core_api.list_namespace()
                logger.info(f"Found {len(namespaces.items)} namespaces.")
            except ApiException as e:
                logger.error(f"Kubernetes API error listing namespaces: {e.status} - {e.reason}. Check RBAC permissions for listing namespaces.")
                # Sleep and retry later if listing namespaces fails
                stop_event.wait(RENEWAL_CHECK_INTERVAL_SECONDS)
                continue
            except Exception as e:
                 logger.error(f"Unexpected error listing namespaces: {e}", exc_info=True)
                 stop_event.wait(RENEWAL_CHECK_INTERVAL_SECONDS)
                 continue


            now = datetime.now(timezone.utc)
            renewal_trigger_time = now + timedelta(days=RENEWAL_THRESHOLD_DAYS)
            total_crs_processed = 0

            # Iterate through each namespace
            for ns in namespaces.items:
                namespace_name = ns.metadata.name
                if stop_event.is_set(): # Check stop event frequently
                    break
                logger.debug(f"Checking for DomainCertificates in namespace: {namespace_name}")

                try:
                    cr_list = k8s_co_api.list_namespaced_custom_object(
                        group=CRD_GROUP,
                        version=CRD_VERSION,
                        plural=CRD_PLURAL,
                        namespace=namespace_name
                    )
                    num_crs_in_ns = len(cr_list.get('items', []))
                    if num_crs_in_ns > 0:
                        logger.info(f"Found {num_crs_in_ns} DomainCertificates in namespace '{namespace_name}'.")
                    total_crs_processed += num_crs_in_ns

                    for item in cr_list.get('items', []):
                        if stop_event.is_set(): break # Check stop event frequently

                        metadata = item.get('metadata', {})
                        spec = item.get('spec', {})
                        status = item.get('status', {})

                        name = metadata.get('name')
                        # Namespace is already known (namespace_name)
                        domain = spec.get('domain')
                        email = spec.get('email')
                        auto_renewal = spec.get('autoRenewal', False)
                        not_after_str = status.get('notAfter')
                        current_state = status.get('state')
                        logger.info(f"Processing CR {namespace_name}/{name} for domain {domain} with state '{current_state}'")

                        if not name or not domain or not email:
                            logger.info(f"Skipping CR {namespace_name}/{name} due to missing name, domain, or email.")
                            continue

                        if not auto_renewal:
                            logger.info(f"Skipping CR {namespace_name}/{name} for domain {domain}: autoRenewal is false.")
                            continue

                        if not not_after_str:
                            logger.info(f"Skipping CR {namespace_name}/{name} for domain {domain}: status.notAfter is not set.")
                            continue

                        # Check for certificates stuck in transitional states
                        if current_state in ["Processing", "Renewing", "Deploying"]:
                            # Check if the certificate has been stuck too long
                            last_transition_time = None
                            if 'conditions' in status:
                                for condition in status['conditions']:
                                    if condition.get('type') == 'Ready':
                                        last_transition_time = condition.get('lastTransitionTime')
                                        break

                            if last_transition_time:
                                try:
                                    # Parse the last transition time
                                    transition_dt = datetime.strptime(last_transition_time, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                                    stuck_duration = now - transition_dt

                                    # If stuck for more than the timeout, reset to Deployed state
                                    if stuck_duration.total_seconds() > STUCK_STATE_TIMEOUT_SECONDS:
                                        logger.warning(f"Certificate {namespace_name}/{name} has been in '{current_state}' state for {stuck_duration} (>{STUCK_STATE_TIMEOUT_SECONDS}s). Resetting to 'Deployed'.")
                                        update_crd_status(
                                            k8s_co_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                                            namespace_name, name, {
                                            "state": "Deployed",
                                            "message": f"Reset from stuck '{current_state}' state after {int(stuck_duration.total_seconds())}s timeout",
                                            "conditions": [{
                                                "type": "Ready",
                                                "status": "True",
                                                "reason": "StateReset",
                                                "message": f"Automatically reset from stuck '{current_state}' state",
                                                "lastTransitionTime": now.strftime('%Y-%m-%dT%H:%M:%SZ')
                                            }]
                                        }, logger)
                                        # After reset, continue with normal processing
                                        current_state = "Deployed"
                                    else:
                                        logger.info(f"Skipping CR {namespace_name}/{name} for domain {domain}: current state is '{current_state}' (stuck for {stuck_duration}).")
                                        continue
                                except (ValueError, TypeError) as e:
                                    logger.warning(f"Could not parse lastTransitionTime '{last_transition_time}' for {namespace_name}/{name}: {e}. Skipping.")
                                    continue
                            else:
                                logger.info(f"Skipping CR {namespace_name}/{name} for domain {domain}: current state is '{current_state}' (no transition time).")
                                continue

                        # States that indicate an operation is already in progress
                        if current_state in ["Processing", "Renewing", "Deploying"]:
                             logger.info(f"Skipping CR {namespace_name}/{name} for domain {domain}: current state is '{current_state}'.")
                             continue

                        try:
                            # Attempt to parse with different potential formats, including timezone info
                            not_after_dt = None
                            formats_to_try = [
                                '%Y-%m-%dT%H:%M:%SZ',        # ISO 8601 UTC (common)
                                '%Y-%m-%dT%H:%M:%S.%fZ',     # ISO 8601 UTC with microseconds
                                '%Y-%m-%d %H:%M:%S %z',      # With timezone offset
                                '%Y-%m-%d %H:%M:%S',         # Naive datetime (assume UTC)
                                '%Y-%m-%dT%H:%M:%S%z',       # ISO 8601 with offset
                            ]
                            for fmt in formats_to_try:
                                try:
                                    not_after_dt = datetime.strptime(not_after_str, fmt)
                                    # If parsed datetime is naive, assume UTC
                                    if not_after_dt.tzinfo is None or not_after_dt.tzinfo.utcoffset(not_after_dt) is None:
                                        not_after_dt = not_after_dt.replace(tzinfo=timezone.utc)
                                    break # Stop trying formats once one works
                                except ValueError:
                                    continue # Try next format

                            if not_after_dt is None:
                                 raise ValueError(f"Could not parse date string '{not_after_str}' with known formats.")

                        except ValueError as e:
                            logger.warning(f"Skipping CR {namespace_name}/{name} for domain {domain}: Could not parse notAfter date '{not_after_str}': {e}")
                            continue

                        # Check if the expiration date is within the renewal threshold
                        if not_after_dt <= renewal_trigger_time:
                            logger.info(f"Certificate for domain {domain} ({namespace_name}/{name}) needs renewal (expires {not_after_str}, threshold {RENEWAL_THRESHOLD_DAYS} days).")

                            # 1. Update CRD status to Renewing
                            update_crd_status(
                                k8s_co_api, CRD_GROUP, CRD_VERSION, CRD_PLURAL,
                                namespace_name, name, { # Use namespace_name here
                                "state": "Renewing",
                                "message": f"Automatic renewal triggered (expires {not_after_str})",
                                "conditions": [{ # Keep existing conditions or replace? Replacing for simplicity here.
                                    "type": "Ready",
                                    "status": "False",
                                    "reason": "Renewing",
                                    "message": f"Automatic renewal triggered (expires {not_after_str})",
                                    "lastTransitionTime": now.strftime('%Y-%m-%dT%H:%M:%SZ')
                                }]
                            }, logger)

                            # 2. Publish renewal request to RabbitMQ
                            renewal_message = {
                                "domain": domain,
                                "email": email,
                                "crd_name": name,
                                "crd_namespace": namespace_name, # Use namespace_name here
                                # "action": "renew" # Optional: Add action if process_cert_request needs it
                            }
                            try:
                                channel.basic_publish(
                                    exchange='',
                                    routing_key=QUEUE_NAME_REQUESTS,
                                    body=json.dumps(renewal_message),
                                    properties=pika.BasicProperties(delivery_mode=2) # Persistent
                                )
                                logger.info(f"Published renewal request for {domain} ({namespace_name}/{name}) to queue '{QUEUE_NAME_REQUESTS}'.")
                            except Exception as pub_e:
                                logger.error(f"Failed to publish renewal request for {domain} ({namespace_name}/{name}): {pub_e}")
                                # Optionally revert CRD status back from Renewing if publish fails?
                                # For now, it will be retried on the next check cycle.

                        else:
                            logger.debug(f"Certificate for domain {domain} ({namespace_name}/{name}) does not need renewal yet (expires {not_after_str}).")

                except ApiException as e:
                    # Log error specific to listing CRs in this namespace and continue
                    logger.error(f"Kubernetes API error listing DomainCertificates in namespace '{namespace_name}': {e.status} - {e.reason}. Check RBAC permissions for this namespace.")
                    # Continue to the next namespace
                except Exception as e:
                    logger.error(f"Unexpected error processing namespace '{namespace_name}': {e}", exc_info=True)
                    # Continue to the next namespace

            if stop_event.is_set():
                 logger.info("Renewal check interrupted.")
            else:
                 logger.info(f"Renewal check finished. Processed {total_crs_processed} CRs across {len(namespaces.items)} namespaces.")

        except ApiException as e:
            # This catches errors not specific to a namespace loop (e.g., initial client issues)
            logger.error(f"Kubernetes API error during renewal check: {e.status} - {e.reason} - {e.body}")
        except Exception as e:
            logger.error(f"Unexpected error during renewal check: {e}", exc_info=True) # Log traceback for unexpected errors

        # Wait for the specified interval or until stop event is set
        logger.debug(f"Sleeping for {RENEWAL_CHECK_INTERVAL_SECONDS} seconds before next renewal check...")
        stop_event.wait(RENEWAL_CHECK_INTERVAL_SECONDS)

    logger.info("Renewal check thread stopped.")


def main():
    """Main function to handle both certificate requests and success events."""
    
    # Run certificate expiry date migration on startup
    logger.info("Running startup migration to fix certificate expiry dates...")
    try:
        migrate_certificate_expiry_dates()
    except Exception as e:
        logger.error(f"Error during startup migration: {e}")
        logger.warning("Continuing with worker startup despite migration error")
    
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

    # --- Start Renewal Check Thread ---
    stop_event = threading.Event()
    renewal_thread = None
    # Check both K8s clients are available
    if k8s_custom_objects_api and k8s_core_v1_api:
        renewal_thread = threading.Thread(
            target=check_and_trigger_renewals,
            args=(channel, k8s_custom_objects_api, k8s_core_v1_api, stop_event), # Pass both clients
            daemon=True # Allows main thread to exit even if this thread is running
        )
        renewal_thread.start()
        logger.info("Renewal check thread started.")
    else:
        logger.warning("One or both Kubernetes clients not available, automatic renewal checks disabled.")
    # --- End Renewal Check Thread ---

    logger.info(f"Unified worker started. Listening for messages on queues '{QUEUE_NAME_REQUESTS}' and '{QUEUE_NAME_DEPLOYMENT}'. To exit press CTRL+C")

    try:
        # Keep main thread alive while consuming
        while True:
             # Process RabbitMQ events for a short time, then loop
             # This allows KeyboardInterrupt to be caught more reliably than channel.start_consuming()
             connection.process_data_events(time_limit=1)
             # Optional: Check if renewal thread is alive and restart if needed
             # Check both K8s clients are available before restarting
             if renewal_thread and not renewal_thread.is_alive() and k8s_custom_objects_api and k8s_core_v1_api:
                 logger.warning("Renewal check thread seems to have stopped unexpectedly. Restarting...")
                 stop_event.clear() # Ensure stop event is clear before restarting
                 renewal_thread = threading.Thread(
                     target=check_and_trigger_renewals,
                     args=(channel, k8s_custom_objects_api, k8s_core_v1_api, stop_event), # Pass both clients
                     daemon=True
                 )
                 renewal_thread.start()

    except KeyboardInterrupt:
        logger.info("Worker stopping...")
        stop_event.set() # Signal renewal thread to stop
        if renewal_thread:
            logger.info("Waiting for renewal check thread to finish...")
            renewal_thread.join(timeout=5) # Wait briefly for thread to exit
            if renewal_thread.is_alive():
                logger.warning("Renewal check thread did not stop gracefully.")
    finally:
        if connection.is_open:
            connection.close()
            logger.info("RabbitMQ connection closed.")
        logger.info("Worker stopped.")

if __name__ == "__main__":
    main()
