#!/usr/bin/env python3
import os, binascii
import argparse

parser = argparse.ArgumentParser(description='Convert binary file to shellcode.')
parser.add_argument('-f', required=True, help='Target binary file.')
parser.add_argument('-o', required=True, help='Output file for shellcode.')
args = parser.parse_args()

target = args.f
output_file = args.o
bytes_per_line = 16

count = 0
index = 0
output = "unsigned char binary[] = {\n\t"
with open(target, "rb") as f:
    hexdata = binascii.hexlify(f.read()).decode()
hexlist = [hexdata[i:i+2] for i in range(0, len(hexdata), 2)]
for hex in hexlist:
    if count >= bytes_per_line:
        output += "\n\t"
        count = 0
    output += "0x" + str(hexlist[index]).upper() + ","
    count += 1
    index += 1
output += "\n};\n"
with open(output_file, "w") as out:
    out.write(output)
