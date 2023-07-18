import re
import argparse

def revert_values(input_file):
    with open(input_file, 'r') as file:
        c_code = file.readlines()

    for i in range(len(c_code)):
        if re.search(r'char\* xorKeyBase64 = ".+";', c_code[i]):
            c_code[i] = re.sub(r'".+"', '"#1"', c_code[i])
        # elif re.search(r'char\* aesKeyBase64 = ".+";', c_code[i]):
        #     c_code[i] = re.sub(r'".+"', '"#2"', c_code[i])
        # elif re.search(r'char\* ivBase64 = ".+";', c_code[i]):
        #     c_code[i] = re.sub(r'".+"', '"#3"', c_code[i])

    with open(input_file, 'w') as file:
        file.writelines(c_code)

revert_values("..\\CLoader\\Sheller\\Sheller\\Encrypters.h")
