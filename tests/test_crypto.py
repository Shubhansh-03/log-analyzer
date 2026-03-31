import sys
import os
import pytest
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keys.generate_keys import generate_key_pair
from client.encryptor import Encryptor
from server.decryptor import Decryptor

@pytest.fixture(scope="module")
def setup_keys():
    os.makedirs("keys", exist_ok=True)
    generate_key_pair("keys", "test_client")
    generate_key_pair("keys", "test_server")
    yield
    # Cleanup
    for f in ["test_client_private.pem", "test_client_public.pem", "test_server_private.pem", "test_server_public.pem"]:
        try:
            os.remove(os.path.join("keys", f))
        except OSError:
            pass

def test_full_encryption_cycle(setup_keys):
    # Initialize client encryptor using client private + server public
    client = Encryptor("keys/test_client_private.pem", "keys/test_server_public.pem")
    
    # Initialize server decryptor using server private + client public
    server = Decryptor("keys/test_server_private.pem", "keys/test_client_public.pem")
    
    original_payload = {
        "device_id": "test_device_1",
        "timestamp": "2026-03-30T12:00:00Z",
        "logs": [
            {"raw_logs": "test log message 1", "log_source": "syslog"},
            {"raw_logs": "test log message 2", "log_source": "auth"}
        ]
    }
    
    # Client Phase
    encrypted_dict = client.encrypt_batch(original_payload)
    
    assert "encrypted_logs" in encrypted_dict
    assert "encrypted_aes_key" in encrypted_dict
    assert "signature" in encrypted_dict
    assert "iv" in encrypted_dict
    
    # Simulate network transfer and server Phase
    decrypted_payload = server.decrypt_and_verify(encrypted_dict)
    
    assert decrypted_payload["device_id"] == original_payload["device_id"]
    assert decrypted_payload["logs"] == original_payload["logs"]

def test_signature_tampering(setup_keys):
    client = Encryptor("keys/test_client_private.pem", "keys/test_server_public.pem")
    server = Decryptor("keys/test_server_private.pem", "keys/test_client_public.pem")
    
    original_payload = {"test": "tamper me"}
    encrypted_dict = client.encrypt_batch(original_payload)
    
    # Tamper the signature by removing the last character
    encrypted_dict['signature'] = encrypted_dict['signature'][:-2] + '==' 
    
    with pytest.raises(ValueError, match="tampered"):
        server.decrypt_and_verify(encrypted_dict)
