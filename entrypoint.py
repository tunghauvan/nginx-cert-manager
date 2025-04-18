#!/usr/bin/env python3
"""
NGINX Certificate Manager - Entrypoint

This is the main entrypoint for the NGINX Certificate Manager application,
which helps automate certificate issuance and installation on NGINX servers.
"""

import argparse
import logging
import os
import sys
from typing import Dict, Any

# Import local modules
from utils.route53 import Route53Manager

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("nginx-cert-manager")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="NGINX Certificate Manager - Automate SSL certificate management for NGINX"
    )

    # Main command subparsers
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Create parser for 'issue' command
    issue_parser = subparsers.add_parser("issue", help="Issue a new SSL certificate")
    issue_parser.add_argument("--domain", "-d", required=True, help="Domain name for the certificate")
    issue_parser.add_argument("--email", "-e", required=True, help="Email address for Let's Encrypt notifications")
    issue_parser.add_argument("--dns-provider", choices=["route53"], default="route53", help="DNS provider for DNS challenge")
    
    # Create parser for 'renew' command
    renew_parser = subparsers.add_parser("renew", help="Renew existing certificates")
    renew_parser.add_argument("--domain", "-d", help="Specific domain to renew (renews all if not specified)")
    
    # Create parser for 'deploy' command
    deploy_parser = subparsers.add_parser("deploy", help="Deploy certificate to NGINX server")
    deploy_parser.add_argument("--domain", "-d", required=True, help="Domain name of the certificate to deploy")
    deploy_parser.add_argument("--server", "-s", required=True, help="NGINX server hostname or IP")
    deploy_parser.add_argument("--username", "-u", required=True, help="SSH username")
    deploy_parser.add_argument("--key-path", "-k", help="Path to SSH private key")
    deploy_parser.add_argument("--password", "-p", help="SSH password (not recommended, use key-based auth)")
    
    # Create parser for 'serve' command
    serve_parser = subparsers.add_parser("serve", help="Start the HTTP agent service")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host to bind the HTTP server to")
    serve_parser.add_argument("--port", "-p", type=int, default=5000, help="Port to listen on")
    serve_parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    serve_parser.add_argument("--cert", help="Path to SSL certificate for HTTPS")
    serve_parser.add_argument("--key", help="Path to SSL key for HTTPS")
    
    # AWS credentials for Route53
    aws_group = parser.add_argument_group("AWS Route53 Configuration")
    aws_group.add_argument("--aws-access-key", help="AWS Access Key ID")
    aws_group.add_argument("--aws-secret-key", help="AWS Secret Access Key")
    aws_group.add_argument("--aws-region", default="us-east-1", help="AWS Region")
    
    # General options
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--config", "-c", help="Path to configuration file")

    return parser.parse_args()


def load_config(config_path: str = None) -> Dict[str, Any]:
    """
    Load configuration from file if specified, otherwise use defaults.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing configuration values
    """
    config = {
        "aws_access_key": os.environ.get("AWS_ACCESS_KEY_ID"),
        "aws_secret_key": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "aws_region": os.environ.get("AWS_REGION", "us-east-1"),
    }
    
    # TODO: Add code to load configuration from file when needed
    
    return config


def issue_certificate(args, config):
    """
    Issue a new SSL certificate using DNS validation.
    
    Args:
        args: Command line arguments
        config: Configuration dictionary
    """
    logger.info(f"Issuing new certificate for {args.domain}")
    
    # Initialize Route53 for DNS validation if using Route53
    if args.dns_provider == "route53":
        route53 = Route53Manager(
            aws_access_key=args.aws_access_key or config.get("aws_access_key"),
            aws_secret_key=args.aws_secret_key or config.get("aws_secret_key"),
            aws_region=args.aws_region or config.get("aws_region")
        )

        # Getting root domain from the domain
        root_domain = args.domain.split(".")[-2] + "." + args.domain.split(".")[-1]
        logger.info(f"Root domain for DNS challenge: {root_domain}")
        
        # Get zone ID for the root domain
        zone_id = route53.get_hosted_zone_id(root_domain)
        if not zone_id:
            logger.error(f"No hosted zone found for root domain {root_domain}")
            return False
        
        logger.info(f"Found hosted zone ID: {zone_id} for root domain {root_domain}")
        
        # Send request to RabbitMQ using utility function
        from utils.rabbitmq import send_rabbitmq_message
        message = {
            "action": "issue_certificate",
            "domain": args.domain,
            "email": args.email,
            "zone_id": zone_id
        }
        if not send_rabbitmq_message("cert_requests", message):
            logger.error("Failed to send request to RabbitMQ")
            return False
        
        # TODO: Implement certificate issuance with Let's Encrypt using DNS challenge
    
    return True


def renew_certificates(args, config):
    """
    Renew existing certificates.
    
    Args:
        args: Command line arguments
        config: Configuration dictionary
    """
    if args.domain:
        logger.info(f"Renewing certificate for {args.domain}")
    else:
        logger.info("Renewing all certificates")
    
    # TODO: Implement certificate renewal logic
    
    return True


def deploy_certificate(args, config):
    """
    Deploy certificate to NGINX server via SSH.
    
    Args:
        args: Command line arguments
        config: Configuration dictionary
    """
    logger.info(f"Deploying certificate for {args.domain} to server {args.server}")
    
    # TODO: Implement SSH deployment logic using the functionality mentioned in the README
    
    return True


def serve_http_agent(args, config):
    """
    Start the HTTP agent service.
    
    Args:
        args: Command line arguments
        config: Configuration dictionary
    """
    try:
        # Import the HTTP agent module here to avoid circular imports
        from agent.http_agent import app
        
        logger.info(f"Starting HTTP agent on {args.host}:{args.port}")
        
        # Configure SSL if certificates are provided
        ssl_context = None
        if args.cert and args.key:
            logger.info("Using SSL with provided certificate and key")
            ssl_context = (args.cert, args.key)
        
        # Start the Flask application
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            ssl_context=ssl_context
        )
        return True
    except ImportError:
        logger.error("Failed to import HTTP agent module. Make sure agent/http_agent.py exists.")
        return False
    except Exception as e:
        logger.error(f"Error starting HTTP agent: {e}")
        return False


def main():
    """Main entry point for the application."""
    args = parse_arguments()
    
    # Set logging level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with command line arguments
    for key in ["aws_access_key", "aws_secret_key", "aws_region"]:
        if getattr(args, key, None):
            config[key] = getattr(args, key)
    
    # Execute requested command
    result = False
    
    if args.command == "issue":
        result = issue_certificate(args, config)
    elif args.command == "renew":
        result = renew_certificates(args, config)
    elif args.command == "deploy":
        result = deploy_certificate(args, config)
    elif args.command == "serve":
        result = serve_http_agent(args, config)
    else:
        logger.error("No command specified. Use --help to see available commands.")
        return 1
    
    # Return appropriate exit code
    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(main())