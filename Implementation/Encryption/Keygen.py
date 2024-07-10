import os
import base64

# Generate a random 256-bit key for AES-256
aes_key = os.urandom(32)
aes_key_base64 = base64.b64encode(aes_key).decode()
print(f"AES-256 Key (Base64): {aes_key_base64}")

# Generate a random 128-bit IV for AES
aes_iv = os.urandom(16)
aes_iv_base64 = base64.b64encode(aes_iv).decode()
print(f"AES IV (Base64): {aes_iv_base64}")

# Generate a random 256-bit key for XOR
xor_key = os.urandom(32)
xor_key_base64 = base64.b64encode(xor_key).decode()
print(f"XOR Key (Base64): {xor_key_base64}")
