from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
import base64 # Import base64 for encoding output
import os # Import os for file operations
import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
# Import AdmissionregistrationV1Api
from kubernetes.client import AdmissionregistrationV1Api

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define placeholder value (base64 encoded empty string)
PLACEHOLDER_B64 = "Cg=="

def generate_ssh_key_pair(key_size=2048):
    """
    Generates an RSA private key and its corresponding public key in OpenSSH format.

    Args:
        key_size (int): The desired key size in bits (e.g., 2048, 4096).

    Returns:
        tuple: A tuple containing:
            - private_key_pem (bytes): The private key serialized in PEM format.
            - public_key_openssh (bytes): The public key serialized in OpenSSH format.
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Serialize private key to PEM format (Traditional OpenSSL for id_rsa compatibility)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL, # Use TraditionalOpenSSL for id_rsa
        encryption_algorithm=serialization.NoEncryption()
    )

    # Get public key
    public_key = private_key.public_key()

    # Serialize public key to OpenSSH format
    public_key_openssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    return private_key_pem, public_key_openssh

def generate_ca_certificate(service_name, namespace, key_size=2048):
    """
    Generates a self-signed CA certificate and its private key, suitable for
    a Kubernetes webhook service.

    Args:
        service_name (str): The name of the Kubernetes Service for the webhook.
        namespace (str): The namespace of the Kubernetes Service.
        key_size (int): The desired key size in bits (e.g., 2048, 4096).

    Returns:
        tuple: A tuple containing:
            - ca_key_pem (bytes): The CA private key serialized in PEM format.
            - ca_cert_pem (bytes): The CA certificate serialized in PEM format.
    """
    # Generate private key for CA
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Construct the Common Name (CN) and Subject Alternative Names (SANs)
    # CN should match the service DNS name within the cluster
    common_name = f"{service_name}.{namespace}.svc"
    # Add SANs for the service name and the full DNS name
    sans = [
        x509.DNSName(common_name),
        x509.DNSName(f"{service_name}.{namespace}.svc.cluster.local") # Optional FQDN,
    ]


    # Define certificate subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Webhook CA"), # Org name
        x509.NameAttribute(NameOID.COMMON_NAME, common_name), # Use the service DNS name
    ])

    # Build the certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Set validity period (e.g., 10 years)
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*10)
    ).add_extension(
        # Basic constraints: Mark as CA
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).add_extension(
        # Add Subject Alternative Names (SANs)
        x509.SubjectAlternativeName(sans), critical=False,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    # Serialize CA private key to PEM
    ca_key_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize CA certificate to PEM
    ca_cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return ca_key_pem, ca_cert_pem

def setup_kubernetes_secrets(namespace, ssh_secret_name="ssh-key-secret", tls_secret_name="webhook-tls-secret", service_name="webhook-service", webhook_config_name="nginx-cert-manager-webhook"):
    """
    Checks for required secrets in Kubernetes, creates/updates them if necessary,
    and updates the specified ValidatingWebhookConfiguration with the CA bundle.

    Args:
        namespace (str): The Kubernetes namespace.
        ssh_secret_name (str): The name for the SSH key secret.
        tls_secret_name (str): The name for the webhook TLS secret.
        service_name (str): The service name used for the webhook TLS certificate CN.
        webhook_config_name (str): The name of the ValidatingWebhookConfiguration to update.
    """
    try:
        # Load Kubernetes configuration (tries in-cluster first, then kubeconfig)
        config.load_kube_config()
        logging.info("Loaded Kubernetes configuration from kubeconfig.")
    except config.ConfigException:
        try:
            config.load_incluster_config()
            logging.info("Loaded Kubernetes configuration from in-cluster service account.")
        except config.ConfigException:
            logging.error("Could not configure Kubernetes client. Neither kubeconfig nor in-cluster config found.")
            return

    v1 = client.CoreV1Api()
    admission_v1 = AdmissionregistrationV1Api() # Instantiate Admission API client
    ssh_secret_populated = False
    tls_secret_populated = False
    ca_bundle_b64 = None # Variable to hold the final CA bundle

    # --- Check SSH Secret ---
    try:
        secret = v1.read_namespaced_secret(name=ssh_secret_name, namespace=namespace)
        logging.info(f"Secret '{ssh_secret_name}' found in namespace '{namespace}'. Checking content...")
        # Check if 'key.pem' and 'id_rsa.pub' exist, are not empty, and are not placeholders
        key_pem_valid = secret.data and \
                        'key.pem' in secret.data and \
                        secret.data['key.pem'] and \
                        secret.data['key.pem'] != PLACEHOLDER_B64
        # Use 'id_rsa.pub' as the key name for the public key
        pub_key_valid = secret.data and \
                        'id_rsa.pub' in secret.data and \
                        secret.data['id_rsa.pub'] and \
                        secret.data['id_rsa.pub'] != PLACEHOLDER_B64

        # Check if 'id_rsa.pub' exists before trying to print it
        if secret.data and 'id_rsa.pub' in secret.data:
            try:
                print(f"Public key content (base64): {secret.data['id_rsa.pub']}") # Print the public key content
                # print decoded public key content
                print(f"Public key content (decoded): {base64.b64decode(secret.data['id_rsa.pub']).decode('utf-8')}") # Print the public key content
            except Exception as print_err:
                logging.warning(f"Could not decode or print public key content: {print_err}")
        else:
            logging.info(f"Key 'id_rsa.pub' not found in secret '{ssh_secret_name}'.")


        if key_pem_valid and pub_key_valid:
            logging.info(f"Secret '{ssh_secret_name}' contains valid 'key.pem' and 'id_rsa.pub'. Skipping creation.")
            ssh_secret_populated = True
        elif secret.data and ('key.pem' in secret.data or 'id_rsa.pub' in secret.data):
             logging.info(f"Secret '{ssh_secret_name}' exists but 'key.pem' or 'id_rsa.pub' is missing, empty, or placeholder. Will attempt creation/overwrite.")
             ssh_secret_populated = False # Treat as not populated
        else:
            # Secret exists but data fields are missing entirely or secret.data is None
            logging.warning(f"Secret '{ssh_secret_name}' exists but is missing 'key.pem'/'id_rsa.pub' data fields or data is empty. Manual check recommended. Will attempt creation/overwrite.")
            ssh_secret_populated = False # Treat as not populated
    except ApiException as e:
        if e.status == 404:
            logging.info(f"Secret '{ssh_secret_name}' not found. Will attempt creation.")
            ssh_secret_populated = False
        else:
            logging.error(f"Error checking secret '{ssh_secret_name}': {e}. Skipping creation.")
            ssh_secret_populated = True # Avoid creation attempt on error
    except KeyError as ke: # Catch potential KeyError specifically if logic missed something
        logging.error(f"KeyError encountered while checking secret '{ssh_secret_name}': {ke}. This might indicate missing data fields.")
        ssh_secret_populated = False # Treat as not populated to attempt overwrite
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking secret '{ssh_secret_name}': {e}")
        ssh_secret_populated = True # Avoid creation attempt on unexpected error


    # --- Create/Update SSH Secret if needed ---
    if not ssh_secret_populated:
        logging.info(f"Creating/Updating secret '{ssh_secret_name}'...")
        try:
            # Generate both private and public keys
            private_pem, public_openssh = generate_ssh_key_pair()
            secret_data = {
                "key.pem": base64.b64encode(private_pem).decode("utf-8"),
                # Add the public key using 'id_rsa.pub' as the key
                "id_rsa.pub": base64.b64encode(public_openssh).decode("utf-8")
            }
            secret_body = client.V1Secret(
                api_version="v1",
                kind="Secret",
                metadata=client.V1ObjectMeta(name=ssh_secret_name, namespace=namespace),
                type="Opaque", # Type remains Opaque
                data=secret_data
            )
            try:
                # Try to update first in case it exists but was deemed incomplete
                v1.replace_namespaced_secret(name=ssh_secret_name, namespace=namespace, body=secret_body)
                logging.info(f"Secret '{ssh_secret_name}' updated successfully.")
            except ApiException as e:
                if e.status == 404: # If it truly doesn't exist, create it
                    v1.create_namespaced_secret(namespace=namespace, body=secret_body)
                    logging.info(f"Secret '{ssh_secret_name}' created successfully.")
                else: # Other API error during replace
                    raise e
        except ApiException as e:
             logging.error(f"Failed to create/update secret '{ssh_secret_name}' (API Error: {e.status} - {e.reason}): {e.body}")
        except Exception as create_err:
            logging.error(f"Failed to create/update secret '{ssh_secret_name}': {create_err}")


    # --- Check Webhook TLS Secret ---
    try:
        secret = v1.read_namespaced_secret(name=tls_secret_name, namespace=namespace)
        logging.info(f"Secret '{tls_secret_name}' found in namespace '{namespace}'. Checking content...")
        # Check if both keys exist, are not empty, and are not placeholders
        tls_crt_valid = secret.data and 'tls.crt' in secret.data and secret.data['tls.crt'] and secret.data['tls.crt'] != PLACEHOLDER_B64
        tls_key_valid = secret.data and 'tls.key' in secret.data and secret.data['tls.key'] and secret.data['tls.key'] != PLACEHOLDER_B64

        if tls_crt_valid and tls_key_valid:
            logging.info(f"Secret '{tls_secret_name}' contains valid 'tls.crt' and 'tls.key'.")
            tls_secret_populated = True
            # Get the caBundle from the existing secret
            ca_bundle_b64 = secret.data.get('tls.crt')
            if not ca_bundle_b64:
                 logging.warning(f"Secret '{tls_secret_name}' exists but 'tls.crt' key is missing. Cannot update webhook CA bundle.")
                 # Decide if we should proceed without updating webhook or stop
                 # For now, we'll log and proceed, but webhook might fail
            else:
                 logging.info(f"Using CA bundle from existing secret '{tls_secret_name}'.")

        elif secret.data and ('tls.crt' in secret.data or 'tls.key' in secret.data):
             logging.info(f"Secret '{tls_secret_name}' exists but 'tls.crt' or 'tls.key' is missing, empty, or placeholder. Will attempt creation/overwrite.")
             tls_secret_populated = False # Treat as not populated
        else:
             # Secret exists but data fields are missing entirely
            logging.warning(f"Secret '{tls_secret_name}' exists but is missing 'tls.crt'/'tls.key' data fields. Manual check recommended. Will attempt creation/overwrite.")
            tls_secret_populated = False # Treat as not populated
    except ApiException as e:
        if e.status == 404:
            logging.info(f"Secret '{tls_secret_name}' not found. Will attempt creation.")
            tls_secret_populated = False
        else:
            logging.error(f"Error checking secret '{tls_secret_name}': {e}. Skipping creation.")
            tls_secret_populated = True # Avoid creation attempt on error
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking secret '{tls_secret_name}': {e}")
        tls_secret_populated = True # Avoid creation attempt on error

    # --- Create Webhook TLS Secret if needed ---
    if not tls_secret_populated:
        logging.info(f"Creating/Updating secret '{tls_secret_name}'...")
        try:
            ca_key, ca_cert = generate_ca_certificate(service_name=service_name, namespace=namespace)
            ca_bundle_b64 = base64.b64encode(ca_cert).decode("utf-8") # Store the generated CA bundle
            secret_data = {
                "tls.crt": ca_bundle_b64,
                "tls.key": base64.b64encode(ca_key).decode("utf-8")
            }
            secret_body = client.V1Secret(
                api_version="v1",
                kind="Secret",
                metadata=client.V1ObjectMeta(name=tls_secret_name, namespace=namespace),
                type="kubernetes.io/tls", # Important: Set type to TLS
                data=secret_data
            )
            try:
                # Try to update first
                v1.replace_namespaced_secret(name=tls_secret_name, namespace=namespace, body=secret_body)
                logging.info(f"Secret '{tls_secret_name}' updated successfully.")
            except ApiException as e:
                if e.status == 404: # If not found, create
                    v1.create_namespaced_secret(namespace=namespace, body=secret_body)
                    logging.info(f"Secret '{tls_secret_name}' created successfully.")
                else: # Other API error during replace
                    raise e

            # Print the caBundle needed for the ValidatingWebhookConfiguration
            # This print might be redundant now as we update it directly
            # print(f"\n--- Required for ValidatingWebhookConfiguration ---")
            # print(f"caBundle (base64 encoded CA Cert from created/updated '{tls_secret_name}'):")
            # print(ca_bundle_b64)
            logging.info(f"Using newly generated CA bundle for secret '{tls_secret_name}'.")

        except ApiException as e:
             logging.error(f"Failed to create/update secret '{tls_secret_name}' (API Error: {e.status} - {e.reason}): {e.body}")
        except Exception as create_err:
            logging.error(f"Failed to create/update secret '{tls_secret_name}': {create_err}")

    # --- Update ValidatingWebhookConfiguration ---
    if ca_bundle_b64:
        logging.info(f"Attempting to update ValidatingWebhookConfiguration '{webhook_config_name}'...")
        try:
            webhook_config = admission_v1.read_validating_webhook_configuration(name=webhook_config_name)

            updated = False
            if webhook_config.webhooks:
                for webhook in webhook_config.webhooks:
                    if webhook.client_config and webhook.client_config.ca_bundle != ca_bundle_b64:
                        logging.info(f"Updating caBundle for webhook '{webhook.name}' in '{webhook_config_name}'.")
                        webhook.client_config.ca_bundle = ca_bundle_b64
                        updated = True
                    elif not webhook.client_config:
                         logging.warning(f"Webhook '{webhook.name}' in '{webhook_config_name}' has no clientConfig. Cannot set caBundle.")
                    elif webhook.client_config.ca_bundle == ca_bundle_b64:
                         logging.info(f"caBundle for webhook '{webhook.name}' in '{webhook_config_name}' is already up-to-date.")


                if updated:
                    # Use patch instead of replace to be safer
                    admission_v1.patch_validating_webhook_configuration(name=webhook_config_name, body=webhook_config)
                    logging.info(f"Successfully patched ValidatingWebhookConfiguration '{webhook_config_name}' with updated caBundle.")
                else:
                    logging.info(f"No caBundle updates needed for ValidatingWebhookConfiguration '{webhook_config_name}'.")
            else:
                logging.warning(f"ValidatingWebhookConfiguration '{webhook_config_name}' has no webhooks defined. Skipping caBundle update.")

        except ApiException as e:
            if e.status == 404:
                logging.error(f"ValidatingWebhookConfiguration '{webhook_config_name}' not found. Cannot update caBundle.")
            else:
                logging.error(f"Failed to read or patch ValidatingWebhookConfiguration '{webhook_config_name}' (API Error: {e.status} - {e.reason}): {e.body}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while updating ValidatingWebhookConfiguration '{webhook_config_name}': {e}")
    else:
        logging.warning(f"No CA bundle available (from existing or new secret '{tls_secret_name}'). Skipping update of ValidatingWebhookConfiguration '{webhook_config_name}'.")


if __name__ == "__main__":
    # Define Kubernetes namespace and service name from environment variables
    # Use Downward API in Kubernetes to inject the namespace
    k8s_namespace = os.environ.get("K8S_NAMESPACE", "nginx-cert-manager") # Default if not set
    webhook_service_name = os.environ.get("WEBHOOK_SERVICE_NAME", "webhook-service") # Default if not set
    # Get the ValidatingWebhookConfiguration name from env var
    webhook_config_name = os.environ.get("VALIDATING_WEBHOOK_CONFIG_NAME", "domaincertificate-validation-webhook") # Default if not set

    # --- Setup Kubernetes Secrets and Update Webhook ---
    logging.info(f"Starting Kubernetes secret setup in namespace '{k8s_namespace}' for service '{webhook_service_name}'...")
    logging.info(f"Will update ValidatingWebhookConfiguration '{webhook_config_name}'.")
    setup_kubernetes_secrets(
        namespace=k8s_namespace,
        service_name=webhook_service_name,
        webhook_config_name=webhook_config_name # Pass the name here
    )
    logging.info("Kubernetes secret and webhook update process finished.")

    # --- Optional: Generate and save keys locally if needed ---
    # This part might not be necessary when running inside the init container,
    # but doesn't hurt to leave unless it causes issues with permissions/paths.
    # Consider removing or commenting out if local saving is not desired in the container context.
    output_dir = "generated_keys_local_run" # Changed dir name to avoid potential conflicts
    # ... rest of the local saving code ...
