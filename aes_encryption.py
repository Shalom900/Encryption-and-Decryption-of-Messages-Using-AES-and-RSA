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
