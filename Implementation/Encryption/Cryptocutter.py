import os
import base64
import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

# Key and Initialization Vector for AES
key = get_random_bytes(32)  # AES-256 key
iv = get_random_bytes(16)   # AES block size

# XOR Key
xor_key = get_random_bytes(32)

def xor_encrypt(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def aes_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def encrypt_file(input_file, output_file):
    with open(input_file, 'rb') as file:
        data = file.read()

    encrypted_data = aes_encrypt(data, key, iv)
    encrypted_data = xor_encrypt(encrypted_data, xor_key)
    encrypted_data = base64.b64encode(encrypted_data)
    
    with open(output_file, 'wb') as enc_file:
        enc_file.write(encrypted_data)

    print("AES Key: ", base64.b64encode(key).decode())
    print("AES IV: ", base64.b64encode(iv).decode())
    print("XOR Key: ", base64.b64encode(xor_key).decode())

    # Replacing values in C# code
    with open('F:\\capstone-adversary-emulation-tool\\Implementation\\C_Loader\\C_Loader.c', 'r') as file:
        csharp_code = file.read()
    csharp_code = csharp_code.replace('#2', base64.b64encode(key).decode(), 1)
    csharp_code = csharp_code.replace('#3', base64.b64encode(iv).decode(), 1)
    csharp_code = csharp_code.replace('#1', base64.b64encode(xor_key).decode(), 1)
    with open('F:\\capstone-adversary-emulation-tool\\Implementation\\C_Loader\\C_Loader.c', 'w') as file:
        file.write(csharp_code)

# Argument parsing
parser = argparse.ArgumentParser(description="Encrypt a file with AES-256, XOR, and base64 encoding")
parser.add_argument('-f', '--file', help='Input file to encrypt', required=True)
parser.add_argument('-o', '--output', help='Output file for encrypted data', required=True)
args = parser.parse_args()

encrypt_file(args.file, args.output)
