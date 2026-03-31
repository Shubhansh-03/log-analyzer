import base64
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

class Encryptor:
    def __init__(self, client_private_key_path, server_public_key_path):
        """
        Initializes the Encryptor.
        Loads the client's private key for signing,
        and the server's public key for encrypting the AES key.
        """
        # Load client private key
        with open(client_private_key_path, 'rb') as f:
            self.client_private_key = RSA.import_key(f.read())
        
        # Load server public key
        with open(server_public_key_path, 'rb') as f:
            self.server_public_key = RSA.import_key(f.read())

    def encrypt_batch(self, payload_dict):
        """
        Encrypts a dictionary payload.
        Returns the final secure payload to be sent to the server.
        """
        raw_data = json.dumps(payload_dict).encode('utf-8')
        
        # 1. Sign the plaintext data
        h = SHA256.new(raw_data)
        signature = pkcs1_15.new(self.client_private_key).sign(h)
        
        # 2. Generate random AES-256 session key and IV
        aes_key = get_random_bytes(32) # length for AES-256
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher_aes.iv
        
        # Pad data for AES (Block size = 16)
        pad_len = 16 - (len(raw_data) % 16)
        padded_data = raw_data + bytes([pad_len] * pad_len)
        
        # 3. Encrypt data with AES
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # 4. Encrypt AES key with Server's RSA Public Key
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Encode everything to base64 for transmission
        return {
            "encrypted_logs": base64.b64encode(encrypted_data).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8')
        }
