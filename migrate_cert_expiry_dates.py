#!/usr/bin/env python3
"""
Migration script to fix incorrect expiry dates in DomainCertificate CRDs.
This script reads actual certificate expiry dates from S3 certificates and updates the CRD status.
"""

import os
import sys
import logging
import boto3
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("cert-migration")

# Configuration
S3_CERT_BUCKET = os.environ.get("S3_CERT_BUCKET", "accesstrade-server-configs")
CRD_GROUP = "cert.nginx.io"
CRD_VERSION = "v1"
CRD_PLURAL = "domaincertificates"

# Initialize Kubernetes client
k8s_custom_objects_api = None
k8s_core_v1_api = None

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
    k8s_core_v1_api = client.CoreV1Api()
    logger.info("Kubernetes clients initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Kubernetes clients: {e}")
    sys.exit(1)


def parse_certificate_from_s3(domain, s3_bucket=None):
    """
    Download and parse certificate from S3 to extract expiry date.
    
    Args:
        domain (str): The domain name for the certificate
        s3_bucket (str): Optional - S3 bucket name (defaults to env var)
        
    Returns:
        dict: Certificate details (notBefore, notAfter, serialNumber) or None if failed
    """
    try:
        s3_bucket = s3_bucket or S3_CERT_BUCKET
        s3_client = boto3.client('s3')
        
        # Download certificate
        cert_key = f"certs/{domain}/{domain}.crt"
        logger.info(f"Downloading certificate for {domain} from s3://{s3_bucket}/{cert_key}")
        
        cert_response = s3_client.get_object(Bucket=s3_bucket, Key=cert_key)
        cert_data = cert_response['Body'].read()
        
        # Parse the certificate
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Extract certificate details
        not_before = cert.not_valid_before_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        not_after = cert.not_valid_after_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        serial_number = str(cert.serial_number)
        
        logger.info(f"Certificate for {domain}: notBefore={not_before}, notAfter={not_after}, serial={serial_number}")
        
        return {
            'notBefore': not_before,
            'notAfter': not_after,
            'serialNumber': serial_number
        }
    except s3_client.exceptions.NoSuchKey:
        logger.warning(f"Certificate not found in S3 for domain {domain}")
        return None
    except Exception as e:
        logger.error(f"Failed to parse certificate for {domain}: {e}")
        return None


def update_crd_status(namespace, name, cert_details):
    """
    Update DomainCertificate CRD status with correct certificate details.
    
    Args:
        namespace (str): Kubernetes namespace
        name (str): CRD name
        cert_details (dict): Certificate details to update
        
    Returns:
        bool: True if update successful, False otherwise
    """
    try:
        # Get current CR
        cr = k8s_custom_objects_api.get_namespaced_custom_object(
            group=CRD_GROUP,
            version=CRD_VERSION,
            namespace=namespace,
            plural=CRD_PLURAL,
            name=name
        )
        
        # Get current status or initialize empty
        current_status = cr.get('status', {})
        
        # Update certificate details
        current_status['notBefore'] = cert_details['notBefore']
        current_status['notAfter'] = cert_details['notAfter']
        current_status['serialNumber'] = cert_details['serialNumber']
        
        # Add/update conditions
        if 'conditions' not in current_status:
            current_status['conditions'] = []
        
        # Update or add Ready condition
        ready_condition = {
            'type': 'Ready',
            'status': 'True',
            'reason': 'CertificateMigrated',
            'message': 'Certificate expiry date corrected from S3 certificate',
            'lastTransitionTime': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        
        # Find and update existing Ready condition or append new one
        ready_found = False
        for i, condition in enumerate(current_status['conditions']):
            if condition.get('type') == 'Ready':
                current_status['conditions'][i] = ready_condition
                ready_found = True
                break
        
        if not ready_found:
            current_status['conditions'].append(ready_condition)
        
        # Update the CR status
        cr['status'] = current_status
        
        k8s_custom_objects_api.patch_namespaced_custom_object_status(
            group=CRD_GROUP,
            version=CRD_VERSION,
            namespace=namespace,
            plural=CRD_PLURAL,
            name=name,
            body=cr
        )
        
        logger.info(f"Successfully updated {namespace}/{name} with correct expiry dates")
        return True
        
    except ApiException as e:
        logger.error(f"Failed to update CRD {namespace}/{name}: {e.status} - {e.reason}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error updating CRD {namespace}/{name}: {e}")
        return False


def migrate_all_certificates(dry_run=False):
    """
    Migrate all DomainCertificate resources across all namespaces.
    
    Args:
        dry_run (bool): If True, only log what would be done without making changes
        
    Returns:
        tuple: (success_count, failure_count, skipped_count)
    """
    success_count = 0
    failure_count = 0
    skipped_count = 0
    
    try:
        # List all namespaces
        namespaces = k8s_core_v1_api.list_namespace()
        logger.info(f"Found {len(namespaces.items)} namespaces to process")
        
        for ns in namespaces.items:
            namespace_name = ns.metadata.name
            logger.info(f"Processing namespace: {namespace_name}")
            
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
                    logger.info(f"No DomainCertificates found in namespace {namespace_name}")
                    continue
                
                logger.info(f"Found {len(crs)} DomainCertificates in namespace {namespace_name}")
                
                for cr in crs:
                    metadata = cr.get('metadata', {})
                    spec = cr.get('spec', {})
                    status = cr.get('status', {})
                    
                    name = metadata.get('name')
                    domain = spec.get('domain')
                    current_state = status.get('state')
                    current_not_after = status.get('notAfter')
                    
                    if not domain:
                        logger.warning(f"Skipping {namespace_name}/{name}: no domain in spec")
                        skipped_count += 1
                        continue
                    
                    logger.info(f"Processing {namespace_name}/{name} for domain {domain} (state: {current_state}, current notAfter: {current_not_after})")
                    
                    # Get certificate details from S3
                    cert_details = parse_certificate_from_s3(domain)
                    
                    if not cert_details:
                        logger.warning(f"Skipping {namespace_name}/{name}: could not parse certificate from S3")
                        skipped_count += 1
                        continue
                    
                    # Check if update is needed
                    if current_not_after == cert_details['notAfter']:
                        logger.info(f"Skipping {namespace_name}/{name}: expiry date already correct")
                        skipped_count += 1
                        continue
                    
                    logger.info(f"Will update {namespace_name}/{name}: {current_not_after} -> {cert_details['notAfter']}")
                    
                    if dry_run:
                        logger.info(f"DRY RUN: Would update {namespace_name}/{name}")
                        success_count += 1
                    else:
                        if update_crd_status(namespace_name, name, cert_details):
                            success_count += 1
                        else:
                            failure_count += 1
                
            except ApiException as e:
                logger.error(f"Error listing DomainCertificates in namespace {namespace_name}: {e.status} - {e.reason}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error processing namespace {namespace_name}: {e}")
                continue
        
    except ApiException as e:
        logger.error(f"Error listing namespaces: {e.status} - {e.reason}")
        return success_count, failure_count, skipped_count
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return success_count, failure_count, skipped_count
    
    return success_count, failure_count, skipped_count


def main():
    """Main migration function."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Migrate DomainCertificate expiry dates from S3 certificates'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run in dry-run mode (no actual changes)'
    )
    parser.add_argument(
        '--namespace',
        type=str,
        help='Only process certificates in the specified namespace'
    )
    parser.add_argument(
        '--name',
        type=str,
        help='Only process the specified DomainCertificate (requires --namespace)'
    )
    
    args = parser.parse_args()
    
    if args.name and not args.namespace:
        logger.error("--name requires --namespace to be specified")
        sys.exit(1)
    
    logger.info("=" * 80)
    logger.info("DomainCertificate Expiry Date Migration")
    logger.info("=" * 80)
    
    if args.dry_run:
        logger.info("Running in DRY RUN mode - no changes will be made")
    
    if args.namespace and args.name:
        # Process single certificate
        logger.info(f"Processing single certificate: {args.namespace}/{args.name}")
        
        try:
            cr = k8s_custom_objects_api.get_namespaced_custom_object(
                group=CRD_GROUP,
                version=CRD_VERSION,
                namespace=args.namespace,
                plural=CRD_PLURAL,
                name=args.name
            )
            
            domain = cr.get('spec', {}).get('domain')
            if not domain:
                logger.error(f"No domain found in {args.namespace}/{args.name}")
                sys.exit(1)
            
            cert_details = parse_certificate_from_s3(domain)
            if not cert_details:
                logger.error(f"Could not parse certificate from S3 for {domain}")
                sys.exit(1)
            
            if args.dry_run:
                logger.info(f"DRY RUN: Would update {args.namespace}/{args.name} with {cert_details}")
                sys.exit(0)
            
            if update_crd_status(args.namespace, args.name, cert_details):
                logger.info("Migration completed successfully")
                sys.exit(0)
            else:
                logger.error("Migration failed")
                sys.exit(1)
                
        except ApiException as e:
            logger.error(f"Failed to get certificate: {e.status} - {e.reason}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            sys.exit(1)
    
    elif args.namespace:
        # Process all certificates in namespace
        logger.error("Processing all certificates in a single namespace not yet implemented")
        logger.error("Please use --name with --namespace or omit both to process all")
        sys.exit(1)
    
    else:
        # Process all certificates
        logger.info("Processing all DomainCertificates in all namespaces")
        success_count, failure_count, skipped_count = migrate_all_certificates(dry_run=args.dry_run)
        
        logger.info("=" * 80)
        logger.info("Migration Summary:")
        logger.info(f"  Successfully updated: {success_count}")
        logger.info(f"  Failed: {failure_count}")
        logger.info(f"  Skipped: {skipped_count}")
        logger.info("=" * 80)
        
        if failure_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == "__main__":
    main()
