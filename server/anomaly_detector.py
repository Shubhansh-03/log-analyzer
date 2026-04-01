import joblib
import torch
import torch.nn as nn
import os
import random
import numpy as np

class TabularTransformer(nn.Module):
    def __init__(self, cont_dim, cat_dims, num_classes, embed_dim=32, num_heads=4, num_layers=2):
        super(TabularTransformer, self).__init__()
        self.embed_dim = embed_dim
        self.cont_embeddings = nn.Parameter(torch.randn(cont_dim, embed_dim))
        self.cat_embeddings = nn.ModuleList([
            nn.Embedding(num_cats, embed_dim) for num_cats in cat_dims
        ])
        self.cls_token = nn.Parameter(torch.randn(1, 1, embed_dim))
        encoder_layer = nn.TransformerEncoderLayer(d_model=embed_dim, nhead=num_heads, dim_feedforward=embed_dim * 4, batch_first=True, dropout=0.1)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.fc = nn.Linear(embed_dim, num_classes)
        
    def forward(self, x_cont, x_cat):
        batch_size = x_cont.shape[0]
        x_cont_emb = x_cont.unsqueeze(2) * self.cont_embeddings.unsqueeze(0)
        x_cat_embs = []
        for i, emb_layer in enumerate(self.cat_embeddings):
            x_cat_embs.append(emb_layer(x_cat[:, i]).unsqueeze(1))
        x_cat_emb = torch.cat(x_cat_embs, dim=1) if x_cat_embs else torch.empty((batch_size, 0, self.embed_dim), device=x_cont.device)
        x_emb = torch.cat([x_cont_emb, x_cat_emb], dim=1)
        cls_tokens = self.cls_token.expand(batch_size, -1, -1)
        x_seq = torch.cat([cls_tokens, x_emb], dim=1)
        out = self.transformer(x_seq)
        cls_out = out[:, 0, :]
        logits = self.fc(cls_out)
        return logits

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
    def __init__(self, if_model_path="models/isolation_forest.pkl", lstm_model_path="models/lstm_model.pt", vocab_path="models/vocab.pkl", transformer_path="models/transformer_model.pt", scaler_path="models/transformer_scaler.pkl", encoders_path="models/transformer_encoders.pkl", target_mapping_path="models/transformer_target_mapping.pkl"):
        self.if_model = None
        self.lstm_model = None
        self.vocab = {}
        self.transformer_model = None
        self.transformer_scaler = None
        self.transformer_encoders = {}
        self.transformer_target_mapping = {}
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

        if os.path.exists(transformer_path) and os.path.exists(scaler_path) and os.path.exists(encoders_path):
            try:
                self.transformer_scaler = joblib.load(scaler_path)
                self.transformer_encoders = joblib.load(encoders_path)
                self.transformer_target_mapping = joblib.load(target_mapping_path)
                
                cat_dims = [len(self.transformer_encoders[col].classes_) for col in self.transformer_encoders]
                self.transformer_model = TabularTransformer(
                    cont_dim=10, cat_dims=cat_dims, num_classes=len(self.transformer_target_mapping),
                    embed_dim=32, num_heads=4, num_layers=2
                )
                self.transformer_model.load_state_dict(torch.load(transformer_path, map_location=self.device))
                self.transformer_model.eval()
            except Exception as e:
                print(f"Warning: Failed to load Transformer model: {e}")

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

    def compute_transformer_anomaly(self, df_dict):
        """
        Mode 3: PyTorch Tabular Transformer inference
        df_dict should contain continuous features and categorical features matching the training.
        """
        if not self.transformer_model or not self.transformer_scaler:
            return 0.5, "UNKNOWN"
            
        cont_features = [
            'Response_Time_ms', 'CPU_Usage_Percent', 'Memory_Usage_MB',
            'Disk_Usage_Percent', 'Network_In_KB', 'Network_Out_KB',
            'Login_Attempts', 'Failed_Transactions', 'Alert_Count', 'Retry_Count'
        ]
        cat_features = ['Source', 'User_Role', 'Service_Type', 'Location']

        try:
            # Prepare continuous
            cont_vals = [[df_dict.get(col, 0) for col in cont_features]]
            cont_scaled = self.transformer_scaler.transform(cont_vals)
            x_cont = torch.tensor(cont_scaled, dtype=torch.float32).to(self.device)

            # Prepare categorical
            cat_vals = []
            for col in cat_features:
                enc = self.transformer_encoders.get(col)
                val = str(df_dict.get(col, 'unknown'))
                # Handle unseen labels by defaulting to 0
                if val in enc.classes_:
                    cat_vals.append(enc.transform([val])[0])
                else:
                    cat_vals.append(0)
            
            x_cat = torch.tensor([cat_vals], dtype=torch.long).to(self.device)
            
            with torch.no_grad():
                logits = self.transformer_model(x_cont, x_cat)
                probs = torch.softmax(logits, dim=1).squeeze()
                
            pred_class = torch.argmax(probs).item()
            pred_severity = self.transformer_target_mapping.get(pred_class, "UNKNOWN")
            
            # Anomaly score based on probability of the predicted severity
            # For anomalies, high severity with high probability = high score
            # Let's just return the probability of being the worst severity class, 
            # or dynamically scale based on the predicted severity class.
            base_score = float(probs[pred_class].item())
            
            # If it's a Low severity, anomaly score is small. Critical gives high anomaly score.
            severity_factor = {'Low': 0.2, 'Medium': 0.5, 'High': 0.8, 'Critical': 1.0}.get(pred_severity, 0.5)
            anomaly_score = round(base_score * severity_factor, 2)
            
            return anomaly_score, pred_severity
            
        except Exception as e:
            print(f"Transformer inference error: {e}")
            return 0.5, "UNKNOWN"
