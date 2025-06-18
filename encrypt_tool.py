import os
import base64
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend

# === Derive AES-256 Key from Password ===
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# === AES Encryption ===
def encrypt_file(filepath, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    with open(filepath, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    enc_file = filepath + ".enc"
    with open(enc_file, 'wb') as f:
        f.write(salt + iv + encrypted)

    return enc_file

# === AES Decryption ===
def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        raw_data = f.read()

    salt, iv, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    dec_file = filepath.replace(".enc", ".dec")
    with open(dec_file, 'wb') as f:
        f.write(data)

    return dec_file

# === GUI ===
def main_gui():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title="Select a file to encrypt/decrypt")

    if not file_path:
        return

    action = simpledialog.askstring("Action", "Type 'encrypt' or 'decrypt':", parent=root)
    if action not in ['encrypt', 'decrypt']:
        messagebox.showerror("Invalid Input", "You must type 'encrypt' or 'decrypt'.")
        return

    password = simpledialog.askstring("Password", "Enter password:", parent=root, show='*')
    if not password:
        messagebox.showerror("Error", "Password is required.")
        return

    try:
        if action == 'encrypt':
            out_file = encrypt_file(file_path, password)
            messagebox.showinfo("Success", f"Encrypted file saved as:\n{out_file}")
        else:
            out_file = decrypt_file(file_path, password)
            messagebox.showinfo("Success", f"Decrypted file saved as:\n{out_file}")
    except Exception as e:
        messagebox.showerror("Operation Failed", str(e))

if __name__ == "__main__":
    main_gui()
