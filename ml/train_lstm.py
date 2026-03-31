import os
import joblib
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server.anomaly_detector import LSTMModel

def get_mock_sequence_data():
    """Generates mock templates and sequences of templates for training"""
    vocab = {"<PAD>": 0}
    sequences = []
    
    # Define some normal sequences representing system events
    normal_flows = [
        ["LOGIN", "ACCESS", "READ", "LOGOUT"],
        ["BOOT", "SERVICE_START", "NETWORK_UP", "CRON_RUN"],
        ["API_GET", "DB_QUERY", "API_RESPOND"],
        ["LOGIN", "SUDO_START", "SUDO_EXEC", "SUDO_END", "LOGOUT"]
    ]
    
    # Hash templates to simulate real parser extraction
    for flow in normal_flows:
        for _ in range(50): # Duplicate
            seq = []
            for item in flow:
                tid = hashlib.md5(item.encode('utf-8')).hexdigest()
                if tid not in vocab:
                    vocab[tid] = len(vocab)
                seq.append(tid)
            sequences.append(seq)
            
    return sequences, vocab

def train_isolation_forest():
    print("Training dummy Isolation Forest baseline...")
    # Generate some dummy data representing [failed_log, err_freq, ip_count, event_rate, burst]
    X = [[0, 0, 1, 10, 0.1] for _ in range(100)]
    X += [[1, 1, 1, 15, 0.2] for _ in range(50)]
    # Anomaly
    X += [[50, 20, 10, 500, 0.9] for _ in range(5)]
    
    clf = IsolationForest(contamination=0.05, random_state=42)
    clf.fit(X)
    joblib.dump(clf, "models/isolation_forest.pkl")

def train_lstm():
    print("Gathering sequence data...")
    sequences, vocab = get_mock_sequence_data()
    
    print("Training PyTorch LSTM...")
    model = LSTMModel(vocab_size=len(vocab))
    
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    criterion = nn.CrossEntropyLoss()
    
    # Convert sequences into inputs and targets (predict next token)
    dataset = []
    for seq in sequences:
        ints = [vocab[tid] for tid in seq]
        for i in range(1, len(ints)):
            dataset.append((ints[:i], ints[i]))
            
    # Simple training loop over 10 epochs
    model.train()
    for epoch in range(10):
        total_loss = 0
        for seq_in, target in dataset:
            optimizer.zero_grad()
            input_tensor = torch.tensor([seq_in], dtype=torch.long)
            target_tensor = torch.tensor([target], dtype=torch.long)
            
            output = model(input_tensor)
            loss = criterion(output, target_tensor)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            
    # Save model and vocab
    torch.save(model.state_dict(), "models/lstm_model.pt")
    joblib.dump(vocab, "models/vocab.pkl")
    print(f"Finished training. Saved models to 'models/'. Vocab size: {len(vocab)}")

if __name__ == "__main__":
    os.makedirs("models", exist_ok=True)
    train_isolation_forest()
    train_lstm()
