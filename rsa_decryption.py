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
