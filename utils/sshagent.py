import os
import paramiko
import socket
import boto3
from urllib.parse import urlparse
from typing import Optional, Tuple, Union, Dict
import tempfile
from dotenv import load_dotenv # Import dotenv


class SSHAgent:
    """SSH Agent for secure connections and file transfers."""
    
    def __init__(self):
        self.client = None
        self.sftp = None
        self.connected = False
    
    def connect(
        self, 
        hostname: str, 
        port: int = 22, 
        username: str = None, 
        password: str = None, 
        key_filename: str = "/root/.ssh/key.pem",
        passphrase: str = None, 
        timeout: int = 10,
        jump_hostname: str = None,
        jump_port: int = 22,
        jump_username: str = None,
        jump_key_filename: str = None,
        jump_passphrase: str = None,
        jump_password: str = None, # Added jump password option
        target_key_on_jump_host: bool = False  # Flag indicating if the target key is on the jump host
    ) -> bool:
        """
        Establish an SSH connection to a remote server, optionally via a jump host.
        
        Args:
            hostname: Target host address
            port: Target SSH port number
            username: Target SSH username
            password: Target SSH password (if using password authentication)
            key_filename: Path to target private key file (defaults to /root/.ssh/keypem)
            passphrase: Passphrase for target key file if needed
            timeout: Connection timeout in seconds
            jump_hostname: Jump host address (optional)
            jump_port: Jump host SSH port number
            jump_username: Jump host SSH username
            jump_key_filename: Path to jump host private key file
            jump_passphrase: Passphrase for jump host key file if needed
            jump_password: Password for jump host (if using password auth for jump)
            target_key_on_jump_host: Whether the target host key is located on jump host
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        self.jump_client = None # Store jump client to close it later if needed
        sock = None
        temp_key_file = None

        try:
            # Step 1: Connect to Jump Host if specified
            if jump_hostname and jump_username:
                print(f"Connecting to jump host: {jump_username}@{jump_hostname}:{jump_port}")
                self.jump_client = paramiko.SSHClient()
                self.jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.jump_client.connect(
                    hostname=jump_hostname,
                    port=jump_port,
                    username=jump_username,
                    key_filename=jump_key_filename,
                    passphrase=jump_passphrase,
                    password=jump_password,
                    timeout=timeout
                )
                print("Connected to jump host.")
                
                # If the target key is on the jump host, retrieve it
                if target_key_on_jump_host and key_filename:
                    print(f"Retrieving key file from jump host: {key_filename}")
                    jump_sftp = self.jump_client.open_sftp()
                    temp_key_file = tempfile.NamedTemporaryFile(delete=False)
                    temp_key_file.close()
                    try:
                        jump_sftp.get(key_filename, temp_key_file.name)
                        # Fix permissions for the key file
                        os.chmod(temp_key_file.name, 0o600)
                        # Use the temporary file instead
                        key_filename = temp_key_file.name
                        print(f"Successfully retrieved key from jump host to {key_filename}")
                    except Exception as e:
                        print(f"Error retrieving key from jump host: {str(e)}")
                        if os.path.exists(temp_key_file.name):
                            os.unlink(temp_key_file.name)
                        return False
                    finally:
                        jump_sftp.close()
                
                # Create a tunnel through the jump host to the target host
                jump_transport = self.jump_client.get_transport()
                dest_addr = (hostname, port)
                # The source address for the channel is from the perspective of the jump host tunnel endpoint
                local_addr = ('127.0.0.1', 0) # Let the OS pick a local port for the tunnel endpoint
                print(f"Opening channel to target {hostname}:{port} via jump host...")
                sock = jump_transport.open_channel("direct-tcpip", dest_addr, local_addr)
                print("Channel opened.")

            # Step 3: Connect to the Target Host (either directly or through the tunnel)
            print(f"Connecting to target host: {username}@{hostname}:{port}")
            self.client.connect(
                hostname=hostname, # Still needed for host key verification if not using AutoAddPolicy strictly
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                passphrase=passphrase,
                timeout=timeout,
                sock=sock # Use the channel as the socket if jump host was used
            )
            self.sftp = self.client.open_sftp()
            self.connected = True
            print(f"Successfully connected to {username}@{hostname}{f' via {jump_username}@{jump_hostname}' if jump_hostname else ''}")
            return True

        except (paramiko.AuthenticationException, 
                paramiko.SSHException, 
                socket.error,
                OSError) as e: 
            print(f"SSH connection error: {str(e)}")
            self.connected = False
            # Ensure jump client is closed if it was opened and connection failed
            if self.jump_client:
                self.jump_client.close()
                self.jump_client = None
            return False
        finally:
            # Clean up temporary key file if created
            if temp_key_file and os.path.exists(temp_key_file.name):
                os.unlink(temp_key_file.name)
                
        # Note: If the main connection succeeds, closing self.client will also close the 
        # underlying channel ('sock') and transport, which should signal the jump_client's
        # transport to clean up. Explicitly closing jump_client in disconnect is safer.

    def disconnect(self) -> None:
        """Close SSH and SFTP connections."""
        if self.sftp:
            self.sftp.close()
            self.sftp = None # Set to None after closing
            
        if self.client:
            self.client.close()
            self.client = None # Set to None after closing

        # Also close the jump client if it exists
        if hasattr(self, 'jump_client') and self.jump_client:
             print("Closing jump host connection.")
             self.jump_client.close()
             self.jump_client = None
            
        self.connected = False
    
    def is_s3_path(self, path: str) -> bool:
        """
        Check if a path is an S3 URL.
        
        Args:
            path: Path to check
            
        Returns:
            bool: True if path is S3 URL, False otherwise
        """
        return path.startswith("s3://")
    
    def execute_command(self, command: str) -> Tuple[int, str, str]:
        """
        Execute a command on the remote server.
        
        Args:
            command: The command to execute
            
        Returns:
            Tuple[int, str, str]: (exit_code, stdout, stderr)
        """
        if not self.connected:
            print("Not connected to SSH server")
            return (-1, "", "Not connected to SSH server")
            
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            return (
                exit_code,
                stdout.read().decode('utf-8').strip(),
                stderr.read().decode('utf-8').strip()
            )
        except Exception as e:
            return (-1, "", str(e))
    
    def upload_from_s3_to_remote(self, s3_path: str, remote_path: str) -> bool:
        """
        Upload a file from S3 to the remote server.
        
        Args:
            s3_path: S3 URI (s3://bucket/key/to/file)
            remote_path: Destination path on the remote server
            
        Returns:
            bool: True if upload successful, False otherwise
        """
        if not self.connected:
            print("Not connected to SSH server")
            return False
            
        if not self.is_s3_path(s3_path):
            print(f"Invalid S3 path: {s3_path}")
            return False
            
        try:
            # Parse S3 URI
            parsed_url = urlparse(s3_path)
            bucket_name = parsed_url.netloc
            key = parsed_url.path.lstrip('/')
            
            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_path = temp_file.name
            temp_file.close()
            
            try:
                # Download from S3
                s3_client = boto3.client('s3')
                print(f"Downloading {s3_path} to temporary file")
                s3_client.download_file(bucket_name, key, temp_path)
                
                # Upload to remote server
                print(f"Uploading to remote server at {remote_path}")
                self.sftp.put(temp_path, remote_path)
                return True
            finally:
                # Clean up temporary file
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                    
        except Exception as e:
            print(f"Error uploading file from S3 to remote: {str(e)}")
            return False
    
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# Usage example:
if __name__ == "__main__":
    load_dotenv() # Load environment variables from .env file

    # Example connection and file transfer
    ssh = SSHAgent()

    # === Direct Connection Example ===
    # print("Attempting direct connection...")
    # connection = ssh.connect(
    #     hostname=os.getenv("TARGET_HOSTNAME"),
    #     username=os.getenv("TARGET_USERNAME"),
    #     key_filename=os.getenv("TARGET_KEY_FILENAME") # Assumes key is local
    # )

    # === Jump Host Connection Example ===
    # Read connection details from environment variables
    target_hostname = os.getenv("TARGET_HOSTNAME")
    target_username = os.getenv("TARGET_USERNAME")
    target_key_filename = os.getenv("TARGET_KEY_FILENAME") # Path on jump host if target_key_on_jump_host is True, else local path
    target_port_str = os.getenv("TARGET_PORT", "22")
    jump_hostname = os.getenv("JUMP_HOSTNAME")
    jump_username = os.getenv("JUMP_USERNAME")
    jump_key_filename = os.getenv("JUMP_KEY_FILENAME") # Optional: Key for jump host itself
    jump_passphrase = os.getenv("JUMP_PASSPHRASE") # Optional: Passphrase for jump host key or target key if on jump host
    jump_port_str = os.getenv("JUMP_PORT", "22")
    target_key_on_jump_host_str = os.getenv("TARGET_KEY_ON_JUMP_HOST", "False").lower()
    target_key_on_jump_host = target_key_on_jump_host_str == 'true'

    # Validate required variables for jump host connection
    required_vars = ["TARGET_HOSTNAME", "TARGET_USERNAME", "TARGET_KEY_FILENAME", "JUMP_HOSTNAME", "JUMP_USERNAME"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]

    if missing_vars:
        print(f"Error: Missing required environment variables for jump host connection: {', '.join(missing_vars)}")
        print("Please ensure TARGET_HOSTNAME, TARGET_USERNAME, TARGET_KEY_FILENAME, JUMP_HOSTNAME, JUMP_USERNAME are set in your .env file.")
        exit(1)

    try:
        target_port = int(target_port_str)
        jump_port = int(jump_port_str)
    except ValueError:
        print("Error: TARGET_PORT or JUMP_PORT environment variable is not a valid integer.")
        exit(1)

    print("Attempting connection via jump host using environment variables...")
    connection = ssh.connect(
        hostname=target_hostname,
        port=target_port,
        username=target_username,
        key_filename=target_key_filename, # Path to target key (potentially on jump host)
        passphrase=os.getenv("TARGET_PASSPHRASE"), # Optional: Passphrase for target key
        jump_hostname=jump_hostname,
        jump_port=jump_port,
        jump_username=jump_username,
        jump_key_filename=jump_key_filename, # Key for jump host authentication
        jump_passphrase=jump_passphrase, # Passphrase for jump host key (or target key if on jump host and encrypted)
        target_key_on_jump_host=target_key_on_jump_host
    )

    if connection:
        print("Connection successful!")
        # Read domain and S3 details from environment variables
        domain = os.getenv("EXAMPLE_DOMAIN", "example.com") # Keep default or make mandatory
        s3_bucket = os.getenv("S3_BUCKET_NAME")
        s3_key_prefix = os.getenv("S3_KEY_PREFIX", f"certs/{domain}") # Default prefix if not set

        if not domain or not s3_bucket:
             print("Error: Missing EXAMPLE_DOMAIN or S3_BUCKET_NAME environment variables.")
             ssh.disconnect()
             exit(1)

        target_dir = f"/etc/letsencrypt/live/{domain}"

        # Execute command create directory if not exists
        print(f"Creating directory {target_dir}...")
        command = f"sudo mkdir -p {target_dir}"
        exit_code, stdout, stderr = ssh.execute_command(command)
        if exit_code == 0:
            print("Directory created or already exists.")
        else:
            print(f"Error creating directory: {stderr}")
            ssh.disconnect() # Disconnect on error
            exit(1) # Exit on error

        # Upload file from S3 to temporary location first
        s3_path = f"s3://{s3_bucket}/{s3_key_prefix}/{domain}.crt"
        temp_remote_path = f"/tmp/{domain}.fullchain.pem" # Use domain in temp name
        final_remote_path = f"{target_dir}/fullchain.pem"

        print(f"Attempting to upload {s3_path} to {temp_remote_path}...")
        if ssh.upload_from_s3_to_remote(s3_path, temp_remote_path):
            print(f"File uploaded successfully to temporary location {temp_remote_path}")
            
            # Move the file to the final destination with sudo and set permissions
            print(f"Moving file to {final_remote_path}...")
            move_command = f"sudo cp {temp_remote_path} {final_remote_path} && sudo chmod 644 {final_remote_path} && sudo rm {temp_remote_path}"
            exit_code, stdout, stderr = ssh.execute_command(move_command)
            
            if exit_code == 0:
                print(f"File successfully moved to {final_remote_path}")
            else:
                print(f"Failed to move file to final destination: {stderr}")
        else:
            print(f"File upload from S3 failed for {s3_path}")
            
        # Disconnect explicitly (though __exit__ handles it too)
        ssh.disconnect()
        print("Disconnected.")
    else:
        print("Connection failed.")