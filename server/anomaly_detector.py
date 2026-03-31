import joblib
import torch
import torch.nn as nn
import os
import random

class LSTMModel(nn.Module):
    def __init__(self, vocab_size, embedding_dim=32, hidden_dim=64):
        super(LSTMModel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, vocab_size)

    def forward(self, x):
        embedded = self.embedding(x)
        out, _ = self.lstm(embedded)
        out = self.fc(out[:, -1, :]) # Predict next token
        return out

class AnomalyDetector:
    def __init__(self, if_model_path="models/isolation_forest.pkl", lstm_model_path="models/lstm_model.pt", vocab_path="models/vocab.pkl"):
        self.if_model = None
        self.lstm_model = None
        self.vocab = {}
        self.device = torch.device("cpu") # For simplicity

        if os.path.exists(if_model_path):
            try:
                self.if_model = joblib.load(if_model_path)
            except Exception as e:
                print(f"Warning: Failed to load Isolation Forest model: {e}")
        
        if os.path.exists(vocab_path):
            try:
                self.vocab = joblib.load(vocab_path)
            except Exception as e:
                print(f"Warning: Failed to load vocab: {e}")
            
        if os.path.exists(lstm_model_path) and hasattr(self, 'vocab') and self.vocab:
            try:
                self.lstm_model = LSTMModel(vocab_size=len(self.vocab))
                self.lstm_model.load_state_dict(torch.load(lstm_model_path, map_location=self.device))
                self.lstm_model.eval()
            except Exception as e:
                print(f"Warning: Failed to load LSTM model: {e}")

    def compute_anomaly_score_mode1(self, features):
        """
        Mode 1: Baseline using Isolation Forest.
        Features expected: [failed_logins, error_freq, unique_ip_count, event_rate, burst_score]
        """
        if not self.if_model:
            # Fallback random prediction for dummy testing
            return round(random.uniform(0.1, 0.4), 2)
            
        try:
            score = self.if_model.decision_function([features])[0]
            # Normalize to 0-1 range (heuristic)
            return round(max(0.0, min(1.0, 0.5 - (score / 2.0))), 2)
        except Exception as e:
            return 0.5

    def compute_anomaly_score_mode2(self, sequence):
        """
        Mode 2: Advanced PyTorch LSTM on a sequence of template IDs.
        Since sequence anomaly detection usually needs historical context (last N tokens),
        we check the probability of the *last* token given the prefix.
        """
        if not self.lstm_model or not self.vocab or len(sequence) < 2:
            return round(random.uniform(0.1, 0.5), 2)
            
        try:
            # Map sequence to integers
            seq_ints = [self.vocab.get(tid, 0) for tid in sequence]
            input_seq = torch.tensor([seq_ints[:-1]], dtype=torch.long)
            target = seq_ints[-1]
            
            with torch.no_grad():
                out = self.lstm_model(input_seq)
                probs = torch.softmax(out, dim=1).squeeze()
                
            prob_of_target = probs[target].item()
            
            # Anomaly score is 1.0 - probability of token
            anomaly_score = 1.0 - prob_of_target
            return round(anomaly_score, 2)
        except Exception as e:
            return 0.5
