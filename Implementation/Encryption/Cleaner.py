import re

def revert_values(input_file):
    with open(input_file, 'r') as file:
        c_code = file.read()

    c_code = re.sub(r'var xorKey = Convert\.FromBase64String\(".+"\);', 'var xorKey = Convert.FromBase64String("#1");', c_code)
    c_code = re.sub(r'var key = Convert\.FromBase64String\(".+"\);', 'var key = Convert.FromBase64String("#2");', c_code)
    c_code = re.sub(r'var iv = Convert\.FromBase64String\(".+"\);', 'var iv = Convert.FromBase64String("#3");', c_code)

    with open(input_file, 'w') as file:
        file.write(c_code)

# Hardcoded file path
input_file = "..\\Loader\\Loader.cs"
revert_values(input_file)
