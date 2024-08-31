### Repository Structure

encryption_decryption_project/Shalom900
│
├── README.md
├── rsa_encryption.py
├── rsa_decryption.py
├── aes_encryption.py
├── aes_decryption.py
└── keys/
    ├── private.pem
    └── public.pem

### 1. **`README.md`**


# Encryption and Decryption in Python

This repository demonstrates the implementation of RSA (asymmetric) and AES (symmetric) encryption techniques using Python. It provides scripts to generate keys, encrypt messages, and decrypt them securely.

## Features

- **RSA Encryption and Decryption**: Secure message transmission using public/private key pairs.
- **AES Encryption and Decryption**: Fast encryption for bulk data using a symmetric key.
- **Key Management**: RSA key generation and secure storage.

## Prerequisites

- **Python 3.x**
- **PyCryptodome** library

### Installation

To install the required dependencies, run:


pip install pycryptodome


## Usage

### 1. RSA Encryption and Decryption

#### Step 1: Generate RSA Keys and Encrypt a Message
- Run `rsa_encryption.py` to generate RSA keys (`private.pem` and `public.pem`) and encrypt a message.

#### Step 2: Decrypt the Encrypted Message
- Replace the placeholder in `rsa_decryption.py` with the base64-encoded encrypted message from `rsa_encryption.py`.
- Run `rsa_decryption.py` to decrypt the message.

### 2. AES Encryption and Decryption

#### Step 1: Encrypt a Message Using AES
- Run `aes_encryption.py` to encrypt a message using a randomly generated AES key.

#### Step 2: Decrypt the Encrypted Message
- Replace the placeholder in `aes_decryption.py` with the base64-encoded encrypted message from `aes_encryption.py`.
- Run `aes_decryption.py` to decrypt the message.

## Directory Structure

- `rsa_encryption.py`: Script to generate RSA keys and encrypt a message.
- `rsa_decryption.py`: Script to decrypt a message encrypted using RSA.
- `aes_encryption.py`: Script to encrypt a message using AES.
- `aes_decryption.py`: Script to decrypt a message encrypted using AES.
- `keys/`: Directory where RSA keys are stored.

## Notes

- Ensure you securely manage the private key (`private.pem`) as it is critical for decrypting messages.
- Do not share your AES key; keep it confidential to maintain the security of your encrypted data.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


### 2. **`rsa_encryption.py`**


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

# Create a directory for keys if it doesn't exist
if not os.path.exists('keys'):
    os.makedirs('keys')

# Generate RSA keys
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Save the keys to files
with open('keys/private.pem', 'wb') as f:
    f.write(private_key)

with open('keys/public.pem', 'wb') as f:
    f.write(public_key)

print("[INFO] RSA keys generated and saved to 'keys/' directory.")

# Encrypt a message
public_key = RSA.import_key(open('keys/public.pem').read())
cipher = PKCS1_OAEP.new(public_key)
plaintext = "THE SECRET OF DARKWEB TECHNOLOGY, STAY TUNE."

encrypted_message = cipher.encrypt(plaintext.encode('utf-8'))

# Encode the encrypted message to base64 for safe transmission/storage
encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
print(f"Encrypted message (base64): {encrypted_message_base64}")


### 3. **`rsa_decryption.py`**


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

# Check if private key exists
private_key_path = 'keys/private.pem'
if not os.path.exists(private_key_path):
    raise FileNotFoundError(f"[ERROR] Private key not found at '{private_key_path}'. Ensure you have generated the key using 'rsa_encryption.py'.")

# Load private key
private_key = RSA.import_key(open(private_key_path).read())
cipher = PKCS1_OAEP.new(private_key)

# Use the actual base64-encoded encrypted message from the encryption step
encrypted_message_base64 = "<INPUT THE GENERATED ENCRYPTED MESSAGE HERE>"  # Replace with actual base64-encoded string
encrypted_message = base64.b64decode(encrypted_message_base64)

# Decrypt the message
decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
print(f"Decrypted message: {decrypted_message}")


### 4. **`aes_encryption.py`**


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def pad(message):
    """Pad message to be a multiple of 16 bytes."""
    return message + ' ' * (16 - len(message) % 16)

# Generate AES key
key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes
cipher = AES.new(key, AES.MODE_EAX)
plaintext = "CYBER SECURITY AND SOFTWARE ENGINEERING TO THE WORLD."
padded_plaintext = pad(plaintext)

# Encrypt the message
ciphertext, tag = cipher.encrypt_and_digest(padded_plaintext.encode('utf-8'))

# Encode the encrypted message to base64 for safe transmission/storage
encrypted_message = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
print(f"Encrypted message: {encrypted_message}")


### 5. **`aes_decryption.py`**

from Crypto.Cipher import AES
import base64

def unpad(message):
    """Remove padding from the decrypted message."""
    return message.rstrip()

# Use the actual base64-encoded encrypted message from the encryption step
encrypted_message = "<INPUT THE ENCRYPTED MESSAGE HERE>"  # Replace with actual base64-encoded string
encrypted_message_bytes = base64.b64decode(encrypted_message)

# Separate the nonce, tag, and ciphertext
nonce, tag, ciphertext = encrypted_message_bytes[:16], encrypted_message_bytes[16:32], encrypted_message_bytes[32:]

# Recreate the cipher object with the original key and nonce
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Print the decrypted message
print(f"Decrypted message: {unpad(decrypted_message)}")


### Enhancements Made:

- **Key Storage**: RSA keys are stored in a dedicated `keys/` directory.
- **Error Handling**: Added checks to ensure the existence of the private key file before attempting decryption.
- **Code Comments**: Provided clear comments for better understanding and maintainability.
- **Padding & Unpadding Functions**: Introduced functions to handle padding for AES encryption and decryption.
- **Professional Formatting**: Improved the readability and organization of both the code and `README.md` file.
