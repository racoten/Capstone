import argparse
import pefile

def extract_shellcode(file_path):
    pe = pefile.PE(file_path)
    # Iterate through sections
    for section in pe.sections:
        # Check if section is executable
        if section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']:
            # Get shellcode from the section
            shellcode = section.get_data()
            print("Shellcode extracted from section:", section.Name.decode("utf-8"))
            return shellcode
    return None

def output_shellcode(shellcode, output_language):
    if output_language == "cs":
        # Output C# byte array
        print("byte[] shellcode = {", end="")
        for i, b in enumerate(shellcode):
            if i != len(shellcode)-1:
                print("0x%02x," % b, end=" ")
            else:
                print("0x%02x" % b, end="")
        print("};")
    elif output_language == "cpp":
        # Output C++ char array
        print("char shellcode[] = {", end="")
        for i, b in enumerate(shellcode):
            if i != len(shellcode)-1:
                print("0x%02x," % b, end=" ")
            else:
                print("0x%02x" % b, end="")
        print("};")
    elif output_language == "py":
        # Output Python bytes array
        print("shellcode = b'", end="")
        for b in shellcode:
            print("\\x%02x" % b, end="")
        print("'")
    elif output_language == "go":
        # Output Go byte array
        print("shellcode := []byte{", end="")
        for i, b in enumerate(shellcode):
            if i != len(shellcode)-1:
                print("0x%02x," % b, end=" ")
            else:
                print("0x%02x" % b, end="")
        print("}")
    elif output_language == "r":
        # Output Rust byte array
        print("let shellcode: [u8; %d] = [" % len(shellcode), end="")
        for i, b in enumerate(shellcode):
            if i != len(shellcode)-1:
                print("0x%02x," % b, end=" ")
            else:
                print("0x%02x" % b, end="")
        print("];")
    else:
        print("Invalid output language option")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract shellcode from a binary")
    parser.add_argument("-f", "--file", required=True, help="Path to the binary file")
    parser.add_argument("-o", "--output", required=True, help="Output language, options are: cs, cpp, py, go, r")
    args = parser.parse_args()

    shellcode = extract_shellcode(args.file)
    if shellcode is not None:
        output_shellcode(shellcode, args.output)
    else:
        print("No shellcode found in binary")
