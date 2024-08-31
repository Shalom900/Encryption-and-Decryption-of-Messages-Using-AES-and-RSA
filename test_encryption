import pytest
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

@pytest.fixture
def rsa_keys():
    # Generate RSA keys
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def test_rsa_encryption_decryption(rsa_keys):
    private_key, public_key = rsa_keys
    
    # Encrypt a message
    public_key_obj = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key_obj)
    plaintext = "THE SECRET OF DARKWEB TECHNOLOGY, STAY TUNE."
    encrypted_message = cipher.encrypt(plaintext.encode('utf-8'))
    
    # Encode to base64 for storage
    encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')

    # Decrypt the message
    private_key_obj = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key_obj)
    encrypted_message_bytes = base64.b64decode(encrypted_message_base64)
    decrypted_message = cipher.decrypt(encrypted_message_bytes).decode('utf-8')
    
    # Verify the decrypted message is the same as the original
    assert decrypted_message == plaintext

@pytest.fixture
def aes_key():
    return get_random_bytes(16)

def test_aes_encryption_decryption(aes_key):
    def pad(message):
        while len(message) % 16 != 0:
            message += ' '
        return message
    
    # Encrypt a message
    cipher = AES.new(aes_key, AES.MODE_EAX)
    plaintext = "CYBER SECURITY AND SOFTWARE ENGINEERING TO THE WORLD."
    padded_plaintext = pad(plaintext)
    ciphertext, tag = cipher.encrypt_and_digest(padded_plaintext.encode('utf-8'))
    
    # Encode to base64 for storage
    encrypted_message = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
    
    # Decrypt the message
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = encrypted_message_bytes[:16], encrypted_message_bytes[16:32], encrypted_message_bytes[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    
    # Verify the decrypted message is the same as the original (after stripping padding)
    assert decrypted_message.strip() == plaintext

