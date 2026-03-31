import base64
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

class Decryptor:
    def __init__(self, server_private_key_path, client_public_key_path):
        """
        Initializes the Decryptor.
        Loads the server's private key for decrypting the AES key,
        and the client's public key for verifying signatures.
        """
        try:
            with open(server_private_key_path, 'rb') as f:
                self.server_private_key = RSA.import_key(f.read())
            
            with open(client_public_key_path, 'rb') as f:
                self.client_public_key = RSA.import_key(f.read())
        except Exception as e:
            print(f"Warning: Keys not loaded during testing/initialization. Ensure keys exist. {e}")
            self.server_private_key = None
            self.client_public_key = None

    def load_keys(self, server_private_key_path, client_public_key_path):
        with open(server_private_key_path, 'rb') as f:
            self.server_private_key = RSA.import_key(f.read())
        with open(client_public_key_path, 'rb') as f:
            self.client_public_key = RSA.import_key(f.read())

    def decrypt_and_verify(self, payload):
        """
        Decrypts a secure payload and verifies its signature.
        Returns the original dictionary of data.
        """
        # Parse base64 strings
        encrypted_logs = base64.b64decode(payload['encrypted_logs'])
        encrypted_aes_key = base64.b64decode(payload['encrypted_aes_key'])
        iv = base64.b64decode(payload['iv'])
        signature = base64.b64decode(payload['signature'])
        
        # 1. Decrypt AES Key using Server's RSA Private Key
        cipher_rsa = PKCS1_OAEP.new(self.server_private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        # 2. Decrypt Payload using AES Key
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        padded_raw_data = cipher_aes.decrypt(encrypted_logs)
        
        # Unpad
        pad_len = padded_raw_data[-1]
        raw_data = padded_raw_data[:-pad_len]
        
        # 3. Verify the Signature
        h = SHA256.new(raw_data)
        try:
            pkcs1_15.new(self.client_public_key).verify(h, signature)
        except (ValueError, TypeError):
            raise ValueError("Signature verification failed. The payload may have been tampered with.")
        
        return json.loads(raw_data.decode('utf-8'))
