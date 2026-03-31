import time
import requests
from datetime import datetime
from config import SERVER_URL, DEVICE_ID, BATCH_INTERVAL, LOG_PATHS, CLIENT_PRIVATE_KEY_PATH, SERVER_PUBLIC_KEY_PATH
from log_collector import LogCollector
from encryptor import Encryptor
import os
import sys

import subprocess

def main():
    if not os.path.exists(CLIENT_PRIVATE_KEY_PATH) or not os.path.exists(SERVER_PUBLIC_KEY_PATH):
        print("Error: Keys not found. Please run the key generation script first.")
        sys.exit(1)

    print(f"Starting log collector for device: {DEVICE_ID}...")
    collector = LogCollector(LOG_PATHS)
    collector.start_collecting(interval=1.0)
    
    encryptor = Encryptor(CLIENT_PRIVATE_KEY_PATH, SERVER_PUBLIC_KEY_PATH)

    print(f"Monitoring logs... Sending batches every {BATCH_INTERVAL} seconds.")
    
    # Ensure bash script is executable
    if os.path.exists("client/get_journal_logs.sh"):
        os.chmod("client/get_journal_logs.sh", 0o755)
    
    try:
        while True:
            # Trigger bash script to fetch journal logs for the last 5 seconds
            try:
                subprocess.run(["./client/get_journal_logs.sh"], check=False)
            except Exception as e:
                print(f"Warning: Failed to run journalctl script: {e}")
                
            time.sleep(BATCH_INTERVAL)
            batch = collector.get_batch()
            
            if not batch:
                continue
                
            print(f"[{datetime.now().isoformat()}] Collected {len(batch)} logs. Encrypting and sending...")
            
            payload_dict = {
                "device_id": DEVICE_ID,
                "timestamp": datetime.now().isoformat(),
                "logs": batch
            }
            
            # Encrypt payload
            try:
                encrypted_payload = encryptor.encrypt_batch(payload_dict)
                encrypted_payload['device_id'] = DEVICE_ID
                encrypted_payload['timestamp'] = payload_dict['timestamp']
            except Exception as e:
                print(f"Encryption failed: {e}")
                continue
            
            # Send to server
            try:
                response = requests.post(SERVER_URL, json=encrypted_payload, timeout=5.0)
                if response.status_code == 200:
                    print(f"  -> Successfully sent. Server Response: {response.json()}")
                else:
                    print(f"  -> Server returned error: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"  -> Network error sending to server: {e}")
                
    except KeyboardInterrupt:
        print("Stopping client.")

if __name__ == "__main__":
    main()
