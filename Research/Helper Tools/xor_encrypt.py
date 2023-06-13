import sys

def xor_encrypt(data, key):
    key_bytes = key.encode()
    key_len = len(key_bytes)
    encrypted_data = bytearray()
    for i, b in enumerate(data):
        encrypted_data.append(b ^ key_bytes[i % key_len])
    return encrypted_data

if __name__ == "__main__":
    file_name = sys.argv[1]
    key = "superstar"
    with open(file_name, "rb") as f:
        data = f.read()
    encrypted_data = xor_encrypt(data, key)
    with open(file_name + ".enc", "wb") as f:
        f.write(encrypted_data)
    print("Successfully encrypted file")
