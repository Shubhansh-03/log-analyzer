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
        Decrypts a secure payload, verifies its signature, and returns events for each step.
        Returns a tuple: (decrypted_data, events_list).
        `decrypted_data` is None on failure.
        """
        events = []
        
        try:
            encrypted_logs = base64.b64decode(payload['encrypted_logs'])
            encrypted_aes_key = base64.b64decode(payload['encrypted_aes_key'])
            iv = base64.b64decode(payload['iv'])
            signature = base64.b64decode(payload['signature'])
        except Exception as e:
            events.append({'event_type': 'Payload Parsing', 'status': 'Failure', 'details': f'Invalid base64 encoding in payload: {e}'})
            return None, events

        # 1. Decrypt AES Key using Server's RSA Private Key
        try:
            cipher_rsa = PKCS1_OAEP.new(self.server_private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            events.append({'event_type': 'RSA Key Decryption', 'status': 'Success', 'details': 'AES session key successfully decrypted.'})
        except Exception as e:
            events.append({'event_type': 'RSA Key Decryption', 'status': 'Failure', 'details': f'Failed to decrypt AES key: {e}'})
            return None, events

        # 2. Decrypt Payload using AES Key
        try:
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
            padded_raw_data = cipher_aes.decrypt(encrypted_logs)
            
            # Unpad
            pad_len = padded_raw_data[-1]
            raw_data = padded_raw_data[:-pad_len]
            events.append({'event_type': 'AES Payload Decryption', 'status': 'Success', 'details': 'Log payload successfully decrypted.'})
        except Exception as e:
            events.append({'event_type': 'AES Payload Decryption', 'status': 'Failure', 'details': f'Failed to decrypt payload: {e}'})
            return None, events

        # 3. Verify the Signature
        try:
            h = SHA256.new(raw_data)
            pkcs1_15.new(self.client_public_key).verify(h, signature)
            events.append({'event_type': 'Signature Verification', 'status': 'Success', 'details': 'Payload signature is valid.'})
        except (ValueError, TypeError):
            events.append({'event_type': 'Signature Verification', 'status': 'Failure', 'details': 'Signature verification failed. Tampering suspected.'})
            return None, events
        
        return json.loads(raw_data.decode('utf-8')), events