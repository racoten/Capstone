import re
import argparse

def revert_values(input_file):
    with open(input_file, 'r') as file:
        csharp_code = file.readlines()

    for i in range(len(csharp_code)):
        if re.search(r'var xorKey = Convert.FromBase64String\(".+"\); // XOR key', csharp_code[i]):
            csharp_code[i] = '\t\t\tvar xorKey = Convert.FromBase64String("#1"); // XOR key\n'
        elif re.search(r'var key = Convert.FromBase64String\(".+"\); // AES-256 key', csharp_code[i]):
            csharp_code[i] = '\t\t\tvar key = Convert.FromBase64String("#2"); // AES-256 key\n'
        elif re.search(r'var iv = Convert.FromBase64String\(".+"\); // AES IV', csharp_code[i]):
            csharp_code[i] = '\t\t\tvar iv = Convert.FromBase64String("#3"); // AES IV\n'

    with open(input_file, 'w') as file:
        file.writelines(csharp_code)

revert_values("F:\\capstone-adversary-emulation-tool\\Implementation\\Loader\\Loader.cs")
