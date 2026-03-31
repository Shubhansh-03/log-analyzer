# Secure Intelligent Log Analysis and Anomaly Detection System

This full-stack system provides a secure, end-to-end mechanism to collect system logs, securely transmit them using Hybrid Cryptography (AES-256 + RSA-2048), parse and classify them, and apply machine learning to detect anomalous behaviors.

## Features
- **Client Agent**: Watchdog-based local file collection.
- **Hybrid Cryptography**: AES-256 CBC payload encryption locked with RSA-2048 PKI.
- **Backend**: FastAPI RESTful backend.
- **Machine Learning**: 
  - Log Classification (RandomForest / TF-IDF)
  - Baseline Anomaly Detection (Isolation Forest)
  - Advanced Sequence Detection (PyTorch LSTM based on sequence templates)
- **Dashboard**: Live real-time visualization using Streamlit.

## Setup Instructions

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Generate Crypto Keys**
   The client and server need RSA keys for encryption and signature verification.
   ```bash
   python keys/generate_keys.py
   ```

3. **Train Machine Learning Models**
   The system relies on models to classify and detect anomalies. Run the training scripts to populate the `models/` directory.
   ```bash
   python ml/train_classifier.py
   python ml/train_lstm.py
   ```

## Running the System

You will need to open three terminal windows to run the full stack locally:

### 1. Start the Server Fast API
Handles decryption, routing, database insertion, and alerting.
```bash
uvicorn server.api:app --host 0.0.0.0 --port 8000
```
OR
```bash
python server/api.py
```

### 2. Start the Dashboard (Streamlit)
Visualizes the data stored in the `secure_logs.db`.
```bash
streamlit run dashboard/app.py
```

### 3. Start the Client Agent
Periodically collects local logs, encrypts payloads, signs them, and sends them to the server.
```bash
python client/sender.py
```

> **Note**: For local testing out-of-the-box, create some dummy data inside `logs/client_custom.log` to watch it trace through the system!

## Testing
Run the pytest suite to verify cryptography and parsing logic:
```bash
pytest tests/
```

## Architecture Summary
- **Client**: `log_collector.py` -> `encryptor.py` -> `sender.py` ---> POST `/receive_logs`
- **Server**: `api.py` -> `decryptor.py` -> `classifier.py` -> `parser_engine.py` -> `anomaly_detector.py` -> `database.py` (SQLite)
- **UI**: `app.py` queries SQLite every 5 seconds.
