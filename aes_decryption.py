from Crypto.Cipher import AES
import base64

def unpad(message):
    """Remove padding from the decrypted message."""
    return message.rstrip()

# Use the actual base64-encoded encrypted message from the encryption step
encrypted_message = "<INPUT THE ENCRYPTED MESSAGE HERE>"  # Replace with the actual base64-encoded string
encrypted_message_bytes = base64.b64decode(encrypted_message)

# Separate the nonce, tag, and ciphertext
nonce, tag, ciphertext = encrypted_message_bytes[:16], encrypted_message_bytes[16:32], encrypted_message_bytes[32:]

# Define or load the AES key (the key must match the one used for encryption)
# Replace with the actual key used during encryption, as a byte string.
key = b'your_16_byte_key_here'  # Example: b'Sixteen byte key' for a 16-byte key

# Recreate the cipher object with the original key and nonce
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Print the decrypted message
print(f"Decrypted message: {unpad(decrypted_message)}")
