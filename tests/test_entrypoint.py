#!/usr/bin/env python3
"""
Unit tests for the entrypoint module.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path to import entrypoint module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import entrypoint
from utils.route53 import Route53Manager


class TestEntrypoint(unittest.TestCase):
    """Test cases for the entrypoint module."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock arguments
        self.mock_args = MagicMock()
        self.mock_args.domain = "example.com"
        self.mock_args.email = "test@example.com"
        self.mock_args.dns_provider = "route53"
        self.mock_args.verbose = False
        self.mock_args.aws_access_key = "test_access_key"
        self.mock_args.aws_secret_key = "test_secret_key"
        self.mock_args.aws_region = "us-west-2"
        
        # Create mock config
        self.mock_config = {
            "aws_access_key": "config_access_key",
            "aws_secret_key": "config_secret_key",
            "aws_region": "us-east-1"
        }

    def test_load_config(self):
        """Test the load_config function."""
        with patch.dict(os.environ, {
            "AWS_ACCESS_KEY_ID": "env_access_key",
            "AWS_SECRET_ACCESS_KEY": "env_secret_key",
            "AWS_REGION": "env_region"
        }):
            config = entrypoint.load_config()
            
            self.assertEqual(config["aws_access_key"], "env_access_key")
            self.assertEqual(config["aws_secret_key"], "env_secret_key")
            self.assertEqual(config["aws_region"], "env_region")
            
        # Test with empty environment
        with patch.dict(os.environ, {}, clear=True):
            config = entrypoint.load_config()
            
            self.assertIsNone(config["aws_access_key"])
            self.assertIsNone(config["aws_secret_key"])
            self.assertEqual(config["aws_region"], "us-east-1")  # Default value

    @patch.object(Route53Manager, "__init__", return_value=None)
    @patch.object(Route53Manager, "get_hosted_zone_id", return_value="Z123456789")
    def test_issue_certificate_success(self, mock_get_zone, mock_init):
        """Test the issue_certificate function with a successful zone lookup."""
        result = entrypoint.issue_certificate(self.mock_args, self.mock_config)
        
        # Verify Route53Manager was initialized with correct credentials
        mock_init.assert_called_once_with(
            aws_access_key="test_access_key",  # Should use args over config
            aws_secret_key="test_secret_key",
            aws_region="us-west-2"
        )
        
        # Verify get_hosted_zone_id was called with the correct domain
        mock_get_zone.assert_called_once_with("example.com")
        
        # Verify the function returned True
        self.assertTrue(result)

    @patch.object(Route53Manager, "__init__", return_value=None)
    @patch.object(Route53Manager, "get_hosted_zone_id", return_value=None)
    def test_issue_certificate_no_zone(self, mock_get_zone, mock_init):
        """Test the issue_certificate function when no zone is found."""
        result = entrypoint.issue_certificate(self.mock_args, self.mock_config)
        
        # Verify get_hosted_zone_id was called with the correct domain
        mock_get_zone.assert_called_once_with("example.com")
        
        # Verify the function returned False
        self.assertFalse(result)

    @patch("argparse.ArgumentParser.parse_args")
    def test_parse_arguments(self, mock_parse_args):
        """Test the argument parsing functionality."""
        # Setup the mock to return our mock_args
        mock_parse_args.return_value = self.mock_args
        
        # Call the function
        args = entrypoint.parse_arguments()
        
        # Verify the mock was called
        mock_parse_args.assert_called_once()
        
        # Verify we got our mock args back
        self.assertEqual(args, self.mock_args)

    def test_renew_certificates(self):
        """Test the renew_certificates function."""
        # Test with a specific domain
        result = entrypoint.renew_certificates(self.mock_args, self.mock_config)
        self.assertTrue(result)
        
        # Test with no domain (renew all)
        self.mock_args.domain = None
        result = entrypoint.renew_certificates(self.mock_args, self.mock_config)
        self.assertTrue(result)

    def test_deploy_certificate(self):
        """Test the deploy_certificate function."""
        # Setup additional mock arguments needed for deploy
        self.mock_args.server = "nginx.example.com"
        self.mock_args.username = "admin"
        self.mock_args.key_path = "/path/to/key"
        
        result = entrypoint.deploy_certificate(self.mock_args, self.mock_config)
        self.assertTrue(result)

    @patch("entrypoint.parse_arguments")
    @patch("entrypoint.load_config")
    @patch("entrypoint.issue_certificate")
    def test_main_issue_command(self, mock_issue, mock_load_config, mock_parse_args):
        """Test the main function with the issue command."""
        # Setup mocks
        mock_args = MagicMock()
        mock_args.command = "issue"
        mock_args.verbose = False
        mock_args.aws_access_key = None
        mock_args.aws_secret_key = None
        mock_args.aws_region = None
        mock_parse_args.return_value = mock_args
        
        mock_config = {"aws_access_key": "config_key", "aws_secret_key": "config_secret", "aws_region": "us-east-1"}
        mock_load_config.return_value = mock_config
        
        mock_issue.return_value = True
        
        # Call the main function
        result = entrypoint.main()
        
        # Verify the expected functions were called
        mock_parse_args.assert_called_once()
        mock_load_config.assert_called_once()
        mock_issue.assert_called_once_with(mock_args, mock_config)
        
        # Verify the function returned the expected exit code
        self.assertEqual(result, 0)

    @patch("entrypoint.parse_arguments")
    def test_main_no_command(self, mock_parse_args):
        """Test the main function with no command specified."""
        # Setup mock to return args with no command
        mock_args = MagicMock()
        mock_args.command = None
        mock_args.verbose = False
        mock_parse_args.return_value = mock_args
        
        # Call the main function
        result = entrypoint.main()
        
        # Verify the function returned the expected exit code
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()