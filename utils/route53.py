"""
AWS Route53 Interaction Module

This module provides functions to interact with AWS Route53 DNS service.
"""

import boto3
import logging
import json
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class Route53Manager:
    """Class to manage AWS Route53 DNS operations."""
    
    def __init__(self, aws_access_key=None, aws_secret_key=None, aws_region='us-east-1'):
        """
        Initialize Route53Manager with AWS credentials.
        
        Args:
            aws_access_key (str, optional): AWS access key ID. If None, credentials from environment or IAM role will be used.
            aws_secret_key (str, optional): AWS secret access key. If None, credentials from environment or IAM role will be used.
            aws_region (str, optional): AWS region. Defaults to 'us-east-1'.
        """
        self.session_kwargs = {}
        if aws_access_key and aws_secret_key:
            self.session_kwargs = {
                'aws_access_key_id': aws_access_key,
                'aws_secret_access_key': aws_secret_key,
                'region_name': aws_region
            }
        self.client = boto3.client('route53', **self.session_kwargs)
        logger.info("Route53Manager initialized")
    
    def list_hosted_zones(self):
        """
        List all hosted zones in Route53.
        
        Returns:
            list: List of hosted zone dictionaries
        """
        try:
            response = self.client.list_hosted_zones()
            return response['HostedZones']
        except ClientError as e:
            logger.error(f"Failed to list hosted zones: {e}")
            raise
    
    def get_hosted_zone_id(self, domain_name):
        """
        Get the hosted zone ID for a given domain name.
        
        Args:
            domain_name (str): Domain name to find the hosted zone for
            
        Returns:
            str: Hosted zone ID if found, None otherwise
        """
        try:
            zones = self.list_hosted_zones()
            for zone in zones:
                # Remove trailing dot from zone name for comparison
                zone_name = zone['Name'].rstrip('.')
                if zone_name == domain_name:
                    # Extract ID from the format '/hostedzone/Z123456789'
                    return zone['Id'].split('/')[-1]
                    
            logger.warning(f"No hosted zone found for domain {domain_name}")
            return None
        except Exception as e:
            logger.error(f"Error finding hosted zone for {domain_name}: {e}")
            raise
    
    def create_dns_record(self, zone_id, record_name, record_type, record_value, ttl=300):
        """
        Create a DNS record in the specified hosted zone.
        
        Args:
            zone_id (str): Hosted zone ID
            record_name (str): DNS record name, e.g., 'example.com' or 'www.example.com'
            record_type (str): DNS record type (A, AAAA, CNAME, TXT, etc.)
            record_value (str or list): Value of the DNS record
            ttl (int, optional): TTL in seconds. Defaults to 300.
            
        Returns:
            dict: API response
        """
        try:
            # Ensure record_value is a list
            if isinstance(record_value, str):
                record_value = [record_value]
                
            # Ensure record name ends with a dot
            if not record_name.endswith('.'):
                record_name = f"{record_name}."
                
            changes = {
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': record_name,
                            'Type': record_type,
                            'TTL': ttl,
                            'ResourceRecords': [{'Value': value} for value in record_value],
                        }
                    }
                ]
            }
            
            response = self.client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch=changes
            )
            
            logger.info(f"Created {record_type} record for {record_name}")
            return response
        except ClientError as e:
            logger.error(f"Failed to create DNS record: {e}")
            raise
    
    def delete_dns_record(self, zone_id, record_name, record_type, record_value, ttl=300):
        """
        Delete a DNS record from the specified hosted zone.
        
        Args:
            zone_id (str): Hosted zone ID
            record_name (str): DNS record name to delete
            record_type (str): DNS record type to delete
            record_value (str or list): Value of the DNS record to delete
            ttl (int, optional): TTL in seconds. Defaults to 300.
            
        Returns:
            dict: API response
        """
        try:
            # Ensure record_value is a list
            if isinstance(record_value, str):
                record_value = [record_value]
                
            # Ensure record name ends with a dot
            if not record_name.endswith('.'):
                record_name = f"{record_name}."
                
            changes = {
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': record_name,
                            'Type': record_type,
                            'TTL': ttl,
                            'ResourceRecords': [{'Value': value} for value in record_value],
                        }
                    }
                ]
            }
            
            response = self.client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch=changes
            )
            
            logger.info(f"Deleted {record_type} record for {record_name}")
            return response
        except ClientError as e:
            logger.error(f"Failed to delete DNS record: {e}")
            raise
    
    def get_dns_records(self, zone_id, record_name=None, record_type=None):
        """
        Get DNS records from a hosted zone with optional filtering.
        
        Args:
            zone_id (str): Hosted zone ID
            record_name (str, optional): Filter by record name
            record_type (str, optional): Filter by record type
            
        Returns:
            list: List of matching DNS records
        """
        try:
            kwargs = {'HostedZoneId': zone_id}
            
            if record_name:
                if not record_name.endswith('.'):
                    record_name = f"{record_name}."
                kwargs['StartRecordName'] = record_name
                
            if record_type:
                kwargs['StartRecordType'] = record_type
                
            response = self.client.list_resource_record_sets(**kwargs)
            records = response['ResourceRecordSets']
            
            # Filter records if needed
            if record_name or record_type:
                filtered_records = []
                for record in records:
                    name_match = not record_name or record['Name'] == record_name
                    type_match = not record_type or record['Type'] == record_type
                    if name_match and type_match:
                        filtered_records.append(record)
                return filtered_records
            
            return records
        except ClientError as e:
            logger.error(f"Failed to get DNS records: {e}")
            raise

    def create_dns_validation_record(self, domain, validation_name, validation_value):
        """
        Create a DNS record for certificate validation.
        
        Args:
            domain: Domain being validated
            validation_name: DNS name for the validation record
            validation_value: Value for the validation record
            
        Returns:
            Boolean indicating success or failure
        """
        zone_id = self.get_hosted_zone_id(domain)
        if not zone_id:
            return False
        
        try:
            # Create the validation record
            self.client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'UPSERT',
                            'ResourceRecordSet': {
                                'Name': validation_name,
                                'Type': 'TXT',
                                'TTL': 300,
                                'ResourceRecords': [
                                    {
                                        'Value': f'"{validation_value}"'
                                    }
                                ]
                            }
                        }
                    ]
                }
            )
            return True
        except Exception as e:
            logger.error(f"Error creating DNS record: {e}")
            return False
    
    def delete_dns_validation_record(self, domain, validation_name, validation_value):
        """
        Delete a DNS validation record.
        
        Args:
            domain: Domain being validated
            validation_name: DNS name for the validation record
            validation_value: Value for the validation record
            
        Returns:
            Boolean indicating success or failure
        """
        zone_id = self.get_hosted_zone_id(domain)
        if not zone_id:
            return False
        
        try:
            # Delete the validation record
            self.client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'DELETE',
                            'ResourceRecordSet': {
                                'Name': validation_name,
                                'Type': 'TXT',
                                'TTL': 300,
                                'ResourceRecords': [
                                    {
                                        'Value': f'"{validation_value}"'
                                    }
                                ]
                            }
                        }
                    ]
                }
            )
            return True
        except Exception as e:
            logger.error(f"Error deleting DNS record: {e}")
            return False

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create Route53 manager
    route53 = Route53Manager()
    
    # Example: List all hosted zones
    try:
        zones = route53.list_hosted_zones()
        print(f"Found {len(zones)} hosted zones:")
        for zone in zones:
            print(f"  - {zone['Name']} (ID: {zone['Id'].split('/')[-1]})")
    except Exception as e:
        print(f"Error: {e}")