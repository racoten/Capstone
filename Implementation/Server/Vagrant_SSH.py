import argparse
import paramiko
import os
import base64
import json
import requests

def ssh_to_server(hostname, port, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port, username, password)
    except paramiko.AuthenticationException:
        print("Failed to connect to the server")
        return None
    else:
        return client

def upload_file(client, local_path, remote_path):
    if client is not None:
        sftp = client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        print(f'File uploaded from {local_path} to {remote_path}')
    else:
        print("Could not establish SSH connection")
        os._exit(1)

def download_file(client, remote_path):
    if client is not None:
        sftp = client.open_sftp()
        with sftp.file(remote_path, 'rb') as f:
            file_data = f.read()
        sftp.close()
        encoded_data = base64.b64encode(file_data)
        # Remove \n and \r before decoding
        # clean_encoded_data = encoded_data.replace(b'\n', b'').replace(b'\r', b'')
        return encoded_data.decode()
    else:
        print("Could not establish SSH connection")
        os._exit(1)


def execute_command(client, command):
    if client is not None:
        stdin, stdout, stderr = client.exec_command(command)
        print(stdout.read().decode(), stderr.read().decode())
    else:
        print("Could not establish SSH connection")
        os._exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description="SSH into a server, upload/download files, and execute commands")
    parser.add_argument('-c', '--command', help="Command to execute on the server")
    parser.add_argument('-uf', '--upload', nargs=2, metavar=('local_path', 'remote_path'), help="Upload a file to the server")
    parser.add_argument('-df', '--download', metavar='remote_path', help="Download a file from the server")
    return parser.parse_args()

# You should replace 'localhost', '2222', 'superstar', and 'superstar' with the actual values for your server
ssh_client = ssh_to_server('localhost', '2222', 'superstar', 'superstar')

args = parse_args()
if args.command:
    execute_command(ssh_client, args.command)
if args.upload:
    local_path, remote_path = args.upload
    upload_file(ssh_client, local_path, remote_path)
if args.download:
    remote_path = args.download
    b64_file = download_file(ssh_client, remote_path)
    
    print(b64_file)
if ssh_client is not None:
    ssh_client.close()