import os
import datetime
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import tkinter as tk

class XOR_Encryption_App:
    def __init__(self, root):
        self.root = root
        self.root.title("XOR Encryption")
        self.create_widgets()

    def create_widgets(self):
        input_label = tk.Label(self.root, text="Enter the plaintext:")
        input_label.pack(padx=5, pady=5)

        self.plaintext_input = tk.Text(self.root, wrap="word", height=5, width=50)
        self.plaintext_input.pack(padx=5, pady=5)

        encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_and_display)
        encrypt_button.pack(padx=5, pady=5)

        clear_button = tk.Button(self.root, text="Clear", command=self.clear_textboxes)
        clear_button.pack(padx=5, pady=5)

        output_label = tk.Label(self.root, text="Encrypted value and key:")
        output_label.pack(padx=5, pady=5)

        self.encrypted_output = tk.Text(self.root, wrap="word", height=5, width=50)
        self.encrypted_output.pack(padx=5, pady=5)

    def generate_key_from_date(self):
        today = datetime.date.today().strftime('%Y-%m-%d')
        md5_hash = hashlib.md5(today.encode('utf-8')).hexdigest()
        key = md5_hash[:16].encode()
        return key

    def xor_encrypt(self, plaintext, key):
        cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8'))
        return ciphertext

    def encrypt_and_display(self):
        plaintext = self.plaintext_input.get("1.0", "end-1c")
        if plaintext:
            key = self.generate_key_from_date()
            ciphertext = self.xor_encrypt(plaintext, key)
            output_text = f"Key: {key}\nCiphertext: {ciphertext.hex()}"
            self.encrypted_output.delete("1.0", "end")
            self.encrypted_output.insert("1.0", output_text)

    def clear_textboxes(self):
        self.plaintext_input.delete("1.0", "end")
        self.encrypted_output.delete("1.0", "end")

def main():
    root = tk.Tk()
    app = XOR_Encryption_App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
