import binascii

def extract_hex_codes(file_path):
    with open(file_path, 'rb') as file:
        binary_data = file.read()
    
    hex_codes = binascii.hexlify(binary_data).decode('utf-8')
    hex_codes_with_prefix = '\\x'.join(hex_codes[i:i+2] for i in range(0, len(hex_codes), 2))
    hex_codes_with_prefix = '\\x' + hex_codes_with_prefix
    
    return hex_codes_with_prefix

# Example usage
executable_path = 'PIC_httpreverse_shell.exe'
hex_codes = extract_hex_codes(executable_path)
print(hex_codes)
