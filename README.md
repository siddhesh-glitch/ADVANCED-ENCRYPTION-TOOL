# ADVANCED-ENCRYPTION-TOOL

*COMPANY*: CODTECH IT SOLUTION

*NAME*: SIDDHESH DILIP REWALE

*INTERN ID*: CT04DG367

*DOMAIN*: Cyber Security & Ethical Hacking

*DURATION*: 4 weeks

*MENTOR*:  Neela Santhosh

🔐 Advanced Encryption Tool — Usage Guide
📝 Project Overview
The Advanced Encryption Tool is a Python-based utility designed to securely encrypt and decrypt files using AES-256 encryption with CBC mode and PKCS7 padding. Built with simplicity and clarity in mind, it uses password-based key derivation (PBKDF2 with HMAC-SHA256) to generate strong encryption keys from user-supplied passwords. This tool is intended to help cybersecurity learners and professionals understand the fundamentals of file encryption and apply them practically, especially within Kali Linux environments.

The tool leverages Python’s cryptography library for cryptographic operations and Tkinter for a lightweight graphical interface that guides the user through file selection and password entry. This approach ensures the tool remains accessible without sacrificing essential security concepts.

⚙️ How the Tool Works
Key Derivation: When encrypting or decrypting, the tool generates a 32-byte AES key derived from the password using PBKDF2-HMAC-SHA256 with 100,000 iterations and a random 16-byte salt. The salt ensures unique keys even if the password is reused.

Encryption: The file data is padded using PKCS7 to align with AES’s 16-byte block size. A random 16-byte Initialization Vector (IV) is generated for CBC mode. The output file contains the salt, IV, and ciphertext concatenated together.

Decryption: The tool extracts the salt and IV from the encrypted file, derives the key with the given password, and decrypts the ciphertext. It removes padding to restore the original data.

GUI Interaction: Users interact with a Tkinter window to select the file, choose whether to encrypt or decrypt, and enter a password securely. Feedback is provided via message dialogs.
![Image](https://github.com/user-attachments/assets/87d8bbe8-1676-44ca-bfe6-04b4f6e76c05)
![Image](https://github.com/user-attachments/assets/5a4f214e-8ea3-463b-a2a7-7d4ef4867c03)
![Image](https://github.com/user-attachments/assets/252ac195-d920-4c86-b8ee-a029824e6202)
