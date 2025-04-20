import subprocess
import logging

logger = logging.getLogger("nginx-cert-manager.certbot_runner")

def run_certbot(domain, email, dns_plugin, config_dir, log_dir):
    """
    Builds and runs the certbot command.

    Args:
        domain (str): Domain name.
        email (str): Email address.
        dns_plugin (str): DNS plugin name.
        config_dir (str): Certbot config directory.
        log_dir (str): Certbot log directory.

    Returns:
        subprocess.CompletedProcess: The result of the subprocess run.
    """
    cmd = [
        "certbot", "certonly", "--non-interactive",
        "--agree-tos", "--email", email,
        "--preferred-challenges", "dns",
        f"--{dns_plugin}",
        "-d", domain,
        "--cert-name", domain.replace(".", "-"),
        "--config-dir", config_dir,
        "--logs-dir", log_dir,
        # "--force-renewal" # Consider adding logic to handle renewal if needed
    ]

    logger.info(f"Running certbot command: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
        return result
    except FileNotFoundError:
        logger.error("Certbot command not found. Is Certbot installed and in the system PATH?")
        # Create a mock result object to indicate failure
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr="Certbot command not found.")
    except Exception as e:
        logger.error(f"An unexpected error occurred while running certbot: {e}")
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr=str(e))

