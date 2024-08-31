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
