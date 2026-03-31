import os
import uuid

# Server endpoint
SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000/receive_logs")

# Client device unique identifier
DEVICE_ID = os.environ.get("DEVICE_ID", str(uuid.uuid4()))

# Batch interval in seconds
BATCH_INTERVAL = int(os.environ.get("BATCH_INTERVAL", 5))

# Log files to monitor (adjust paths based on permissions or use synthetic logs in /tmp)
LOG_PATHS = {
    "syslog": "/var/log/syslog",
    "auth": "/var/log/auth.log",
    "custom": "logs/client_custom.log",
    "journal": "logs/journal_temp.log"
}

# Key paths
CLIENT_PRIVATE_KEY_PATH = "keys/client_private.pem"
CLIENT_PUBLIC_KEY_PATH = "keys/client_public.pem"
SERVER_PUBLIC_KEY_PATH = "keys/server_public.pem"

# Ensure directories exist
os.makedirs("keys", exist_ok=True)
os.makedirs("logs", exist_ok=True)
