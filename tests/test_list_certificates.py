#!/usr/bin/env python3
"""
Tests for the certificate listing functionality.
"""

import os
import sys
import unittest
import json
import tempfile
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the HTTP agent module
from agent.http_agent import app, CertificateManager


class TestListCertificates(unittest.TestCase):
    """Test the certificate listing functionality."""

    def setUp(self):
        """Set up test client and test data directory."""
        self.app = app.test_client()
        self.app.testing = True
        
        # Create a temporary directory for test certificates
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Mock the certificates directory in CertificateManager
        self.cert_manager_patcher = patch.object(
            CertificateManager, '__init__', 
            return_value=None
        )
        self.mock_cert_manager_init = self.cert_manager_patcher.start()
        
        # Set the certificates_dir attribute directly
        from agent.http_agent import certificate_manager
        certificate_manager.certificates_dir = self.temp_dir.name
        
        # Create some test certificate data
        self.create_test_certificates()
        
    def tearDown(self):
        """Clean up after tests."""
        self.cert_manager_patcher.stop()
        self.temp_dir.cleanup()
        
    def create_test_certificates(self):
        """Create test certificate data in the temporary directory."""
        # Create a few mock certificates
        certificates = [
            {
                'id': 'cert1',
                'domain': 'example.com',
                'email': 'admin@example.com',
                'issued_at': '2023-01-01 12:00:00',
                'expires_at': '2023-12-31',
                'status': 'valid',
                'issuer': "Let's Encrypt"
            },
            {
                'id': 'cert2',
                'domain': 'test.example.com',
                'email': 'admin@example.com',
                'issued_at': '2023-02-15 08:30:00',
                'expires_at': '2023-05-15',
                'status': 'expired',
                'issuer': "Let's Encrypt"
            },
            {
                'id': 'cert3',
                'domain': 'api.example.com',
                'email': 'admin@example.com',
                'issued_at': '2023-03-10 15:45:00',
                'expires_at': '2023-06-10',
                'status': 'valid',
                'issuer': "Let's Encrypt"
            }
        ]
        
        # Write each certificate to a file
        for cert in certificates:
            # Create directory for this certificate
            cert_dir = os.path.join(self.temp_dir.name, cert['id'])
            os.makedirs(cert_dir, exist_ok=True)
            
            # Write certificate data to file
            with open(os.path.join(cert_dir, 'certificate.json'), 'w') as f:
                json.dump(cert, f)
    
    def test_list_certificates_endpoint(self):
        """Test the list certificates endpoint."""
        # Make request with authentication
        response = self.app.get(
            '/api/v1/certificates',
            headers={'Authorization': 'Bearer test-token'}
        )
        data = json.loads(response.data)
        
        # Check that the response is successful
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data['success'])
        
        # Check that we got all three certificates
        self.assertEqual(len(data['certificates']), 3)
        
        # Check that each certificate has the expected fields
        for cert in data['certificates']:
            self.assertIn('id', cert)
            self.assertIn('domain', cert)
            self.assertIn('status', cert)
            self.assertIn('issued_at', cert)
            self.assertIn('expires_at', cert)
            
        # Check for specific domains to make sure everything loaded correctly
        domains = [cert['domain'] for cert in data['certificates']]
        self.assertIn('example.com', domains)
        self.assertIn('test.example.com', domains)
        self.assertIn('api.example.com', domains)
        
    def test_unauthorized_access(self):
        """Test that unauthorized requests are rejected."""
        response = self.app.get(
            '/api/v1/certificates',
            headers={}  # No auth header
        )
        
        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
