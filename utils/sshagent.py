import os
import paramiko
import socket
import boto3
from urllib.parse import urlparse
from typing import Optional, Tuple, Union, Dict
import tempfile


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
        timeout: int = 10
    ) -> bool:
        """
        Establish an SSH connection to a remote server.
        
        Args:
            hostname: Remote host address
            port: SSH port number
            username: SSH username
            password: SSH password (if using password authentication)
            key_filename: Path to private key file (defaults to /root/.ssh/keypem)
            passphrase: Passphrase for key file if needed
            timeout: Connection timeout in seconds
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                passphrase=passphrase,
                timeout=timeout,
            )
            self.sftp = self.client.open_sftp()
            self.connected = True
            return True
        except (paramiko.AuthenticationException, 
                paramiko.SSHException, 
                socket.error) as e:
            print(f"SSH connection error: {str(e)}")
            self.connected = False
            return False
    
    def disconnect(self) -> None:
        """Close SSH and SFTP connections."""
        if self.sftp:
            self.sftp.close()
            
        if self.client:
            self.client.close()
            
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
    # Example connection and file transfer
    ssh = SSHAgent()
    
    # Connect with password
    connection = ssh.connect(
        hostname="172.31.35.222",
        username="ubuntu"
    )
    
    # Alternative: Connect with key
    # connection = ssh.connect(
    #     hostname="example.com", 
    #     username="user",
    #     key_filename="/path/to/private/key"
    # )
    
    if connection:
        domain = "demo-1.asean-accesstrade.net"
        target_dir = f"/etc/letsencrypt/live/{domain}"
        
        # Execute command create directory if not exists
        command = f"sudo mkdir -p {target_dir}"
        exit_code, stdout, stderr = ssh.execute_command(command)
        
        # Upload file from S3 to temporary location first
        s3_path = f"s3://accesstrade-server-configs/certs/{domain}/{domain}.crt"
        temp_remote_path = f"/tmp/fullchain.pem"
        final_remote_path = f"{target_dir}/fullchain.pem"
        
        if ssh.upload_from_s3_to_remote(s3_path, temp_remote_path):
            print(f"File uploaded successfully to temporary location {temp_remote_path}")
            
            # Move the file to the final destination with sudo and set permissions
            move_command = f"sudo cp {temp_remote_path} {final_remote_path} && sudo chmod 644 {final_remote_path} && rm {temp_remote_path}"
            exit_code, stdout, stderr = ssh.execute_command(move_command)
            
            if exit_code == 0:
                print(f"File successfully moved to {final_remote_path}")
            else:
                print(f"Failed to move file to final destination: {stderr}")
        else:
            print("File upload failed")