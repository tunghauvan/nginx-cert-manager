#!/usr/bin/env python3
"""
Test-driven development for the HTTP middle agent component.
Tests the API bridge between HTTP clients and SSH-based NGINX servers.
"""

import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the module we'll be building (doesn't exist yet, but TDD!)
from agent.http_agent import app, CertificateManager, SSHBridge


class TestHTTPAgentAPI(unittest.TestCase):
    """Test the HTTP API endpoints for the middle agent."""

    def setUp(self):
        """Set up test client and mocks."""
        self.app = app.test_client()
        self.app.testing = True
        
        # Mock the CertificateManager and SSHBridge
        self.cert_manager_mock = MagicMock(spec=CertificateManager)
        self.ssh_bridge_mock = MagicMock(spec=SSHBridge)
        
        # Create patch objects
        self.cert_manager_patcher = patch('agent.http_agent.certificate_manager', 
                                          self.cert_manager_mock)
        self.ssh_bridge_patcher = patch('agent.http_agent.ssh_bridge', 
                                        self.ssh_bridge_mock)
        
        # Start patchers
        self.cert_manager_patcher.start()
        self.ssh_bridge_patcher.start()
    
    def tearDown(self):
        """Clean up patches."""
        self.cert_manager_patcher.stop()
        self.ssh_bridge_patcher.stop()

    def test_health_check(self):
        """Test the health check endpoint."""
        response = self.app.get('/api/v1/health')
        data = json.loads(response.data)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], 'ok')
        self.assertIn('version', data)

    def test_issue_certificate_endpoint(self):
        """Test the issue certificate endpoint."""
        # Mock certificate manager to return a successful result
        self.cert_manager_mock.issue_certificate.return_value = {
            'success': True,
            'certificate_id': '12345',
            'domain': 'example.com',
            'expiry': '2023-12-31'
        }
        
        # Test data
        payload = {
            'domain': 'example.com',
            'email': 'admin@example.com'
        }
        
        # Make request
        response = self.app.post('/api/v1/certificates/issue',
                                json=payload,
                                headers={'Authorization': 'Bearer test-token'})
        data = json.loads(response.data)
        
        # Assertions
        self.assertEqual(response.status_code, 201)
        self.assertTrue(data['success'])
        self.assertEqual(data['certificate_id'], '12345')
        
        # Verify cert manager was called with correct arguments
        self.cert_manager_mock.issue_certificate.assert_called_once_with(
            'example.com', 'admin@example.com'
        )

    def test_deploy_certificate_endpoint(self):
        """Test the deploy certificate endpoint."""
        # Mock SSH bridge to return a successful deployment
        self.ssh_bridge_mock.deploy_certificate.return_value = {
            'success': True,
            'server': 'nginx.example.com',
            'status': 'deployed'
        }
        
        # Test data
        payload = {
            'certificate_id': '12345',
            'server': 'nginx.example.com',
            'vhost': 'example.com'
        }
        
        # Make request
        response = self.app.post('/api/v1/certificates/deploy',
                                json=payload,
                                headers={'Authorization': 'Bearer test-token'})
        data = json.loads(response.data)
        
        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data['success'])
        self.assertEqual(data['server'], 'nginx.example.com')
        
        # Verify SSH bridge was called with correct arguments
        self.ssh_bridge_mock.deploy_certificate.assert_called_once_with(
            '12345', 'nginx.example.com', 'example.com'
        )
        
    def test_unauthorized_access(self):
        """Test that unauthorized requests are rejected."""
        response = self.app.post('/api/v1/certificates/issue',
                               json={'domain': 'example.com'},
                               headers={}) # No auth header
        
        self.assertEqual(response.status_code, 401)
        
    def test_certificate_status_endpoint(self):
        """Test the certificate status endpoint."""
        # Mock certificate manager to return certificate status
        self.cert_manager_mock.get_certificate_status.return_value = {
            'domain': 'example.com',
            'status': 'valid',
            'expiry': '2023-12-31',
            'issuer': "Let's Encrypt"
        }
        
        # Make request
        response = self.app.get('/api/v1/certificates/12345',
                              headers={'Authorization': 'Bearer test-token'})
        data = json.loads(response.data)
        
        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['domain'], 'example.com')
        self.assertEqual(data['status'], 'valid')
        
        # Verify cert manager was called with correct certificate ID
        self.cert_manager_mock.get_certificate_status.assert_called_once_with('12345')


class TestCertificateManager(unittest.TestCase):
    """Test the CertificateManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a CertificateManager with mocked dependencies
        self.cert_manager = CertificateManager()
        
    @patch('agent.http_agent.Route53Manager')
    @patch('agent.http_agent.subprocess.run')
    def test_issue_certificate(self, mock_subprocess, mock_route53):
        """Test issuing a certificate."""
        # Mock Route53 to return a zone ID
        mock_route53_instance = MagicMock()
        mock_route53_instance.get_hosted_zone_id.return_value = 'Z123456789'
        mock_route53.return_value = mock_route53_instance
        
        # Mock subprocess to simulate successful certbot execution
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = 'Certificate issued successfully!'
        
        # Issue a certificate
        result = self.cert_manager.issue_certificate('example.com', 'admin@example.com')
        
        # Assertions
        self.assertTrue(result['success'])
        self.assertEqual(result['domain'], 'example.com')
        self.assertIn('certificate_id', result)
        
        # Verify Route53 was used for DNS validation
        mock_route53_instance.get_hosted_zone_id.assert_called_once_with('example.com')
    

class TestSSHBridge(unittest.TestCase):
    """Test the SSHBridge class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.ssh_bridge = SSHBridge()
    
    @patch('agent.http_agent.paramiko.SSHClient')
    def test_deploy_certificate(self, mock_ssh_client):
        """Test deploying a certificate to a server via SSH."""
        # Mock SSH client
        mock_client_instance = MagicMock()
        mock_ssh_client.return_value = mock_client_instance
        
        # Mock successful command execution
        stdin = MagicMock()
        stdout = MagicMock()
        stdout.read.return_value = b'Certificate deployed and NGINX restarted'
        stderr = MagicMock()
        stderr.read.return_value = b''
        
        mock_client_instance.exec_command.return_value = (stdin, stdout, stderr)
        
        # Deploy certificate
        result = self.ssh_bridge.deploy_certificate(
            certificate_id='12345',
            server='nginx.example.com',
            vhost='example.com'
        )
        
        # Assertions
        self.assertTrue(result['success'])
        self.assertEqual(result['server'], 'nginx.example.com')
        self.assertEqual(result['status'], 'deployed')
        
        # Verify SSH client was connected to correct server
        mock_client_instance.connect.assert_called_once_with('nginx.example.com', 
                                                           username=unittest.mock.ANY,
                                                           key_filename=unittest.mock.ANY)


if __name__ == '__main__':
    unittest.main()