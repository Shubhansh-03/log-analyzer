import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import sys

# Add server directory to path if needed to save/share the model, but we will put it in models/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_PATH = "data/logging_monitoring_anomalies.csv"
MODEL_DIR = "models"
TRANSFORMER_MODEL_PATH = os.path.join(MODEL_DIR, "transformer_model.pt")
SCALER_PATH = os.path.join(MODEL_DIR, "transformer_scaler.pkl")
LABEL_ENCODERS_PATH = os.path.join(MODEL_DIR, "transformer_encoders.pkl")
TARGET_MAPPING_PATH = os.path.join(MODEL_DIR, "transformer_target_mapping.pkl")

# Define features
CONT_FEATURES = [
    'Response_Time_ms', 'CPU_Usage_Percent', 'Memory_Usage_MB',
    'Disk_Usage_Percent', 'Network_In_KB', 'Network_Out_KB',
    'Login_Attempts', 'Failed_Transactions', 'Alert_Count', 'Retry_Count'
]

CAT_FEATURES = [
    'Source', 'User_Role', 'Service_Type', 'Location'
]

TARGET = 'Severity'

class TabularDataset(Dataset):
    def __init__(self, X_cont, X_cat, y):
        self.X_cont = torch.tensor(X_cont, dtype=torch.float32)
        self.X_cat = torch.tensor(X_cat, dtype=torch.long)
        self.y = torch.tensor(y, dtype=torch.long)
        
    def __len__(self):
        return len(self.y)
        
    def __getitem__(self, idx):
        return self.X_cont[idx], self.X_cat[idx], self.y[idx]

class TabularTransformer(nn.Module):
    def __init__(self, cont_dim, cat_dims, num_classes, embed_dim=32, num_heads=4, num_layers=2):
        super(TabularTransformer, self).__init__()
        
        self.embed_dim = embed_dim
        
        # Continuous feature embeddings: each continuous feature gets its own linear transformation mapping scalar -> vector
        # Shape: (cont_dim, embed_dim)
        self.cont_embeddings = nn.Parameter(torch.randn(cont_dim, embed_dim))
        
        # Categorical feature embeddings
        self.cat_embeddings = nn.ModuleList([
            nn.Embedding(num_cats, embed_dim) for num_cats in cat_dims
        ])
        
        # CLS token
        self.cls_token = nn.Parameter(torch.randn(1, 1, embed_dim))
        
        # Transformer
        encoder_layer = nn.TransformerEncoderLayer(d_model=embed_dim, nhead=num_heads, dim_feedforward=embed_dim * 4, batch_first=True, dropout=0.1)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # Classification head
        self.fc = nn.Linear(embed_dim, num_classes)
        
    def forward(self, x_cont, x_cat):
        batch_size = x_cont.shape[0]
        
        # 1. Embed continuous features
        # x_cont is [B, cont_dim]
        # output is [B, cont_dim, embed_dim]
        # Multiply each feature value by its corresponding embedding vector
        x_cont_emb = x_cont.unsqueeze(2) * self.cont_embeddings.unsqueeze(0)
        
        # 2. Embed categorical features
        x_cat_embs = []
        for i, emb_layer in enumerate(self.cat_embeddings):
            x_cat_embs.append(emb_layer(x_cat[:, i]).unsqueeze(1))
            
        x_cat_emb = torch.cat(x_cat_embs, dim=1) if x_cat_embs else torch.empty((batch_size, 0, self.embed_dim), device=x_cont.device)
        
        # 3. Concatenate all embeddings
        x_emb = torch.cat([x_cont_emb, x_cat_emb], dim=1)
        
        # 4. Add CLS token
        cls_tokens = self.cls_token.expand(batch_size, -1, -1)
        x_seq = torch.cat([cls_tokens, x_emb], dim=1)
        
        # 5. Transformer Pass
        out = self.transformer(x_seq)
        
        # 6. Pooling (take the CLS token output)
        cls_out = out[:, 0, :]
        
        # 7. Classification
        logits = self.fc(cls_out)
        return logits

def train_transformer():
    print(f"Loading data from {DATA_PATH}...")
    if not os.path.exists(DATA_PATH):
        print(f"Dataset {DATA_PATH} not found!")
        return
        
    df = pd.read_csv(DATA_PATH)
    print(f"Dataset shape: {df.shape}")
    
    # Preprocessing target
    target_mapping = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
    df[TARGET] = df[TARGET].map(target_mapping)
    # Filter unmapped
    df = df.dropna(subset=[TARGET])
    
    # Preprocessing continuous features
    scaler = StandardScaler()
    X_cont = scaler.fit_transform(df[CONT_FEATURES].fillna(0))
    
    # Preprocessing categorical features
    label_encoders = {}
    X_cat = np.zeros((df.shape[0], len(CAT_FEATURES)), dtype=np.int64)
    cat_dims = []
    
    for i, col in enumerate(CAT_FEATURES):
        le = LabelEncoder()
        # Convert to string and handle NaN
        df[col] = df[col].astype(str).fillna('unknown')
        X_cat[:, i] = le.fit_transform(df[col])
        label_encoders[col] = le
        cat_dims.append(len(le.classes_))
        
    y = df[TARGET].values.astype(np.int64)
    
    # Save the preprocessing objects early
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(label_encoders, LABEL_ENCODERS_PATH)
    target_mapping_reverse = {v: k for k, v in target_mapping.items()}
    joblib.dump(target_mapping_reverse, TARGET_MAPPING_PATH)
    
    # Prepare DataLoader
    # Subset a bit to make training faster for this demo
    dataset_size = len(y)
    indices = np.random.permutation(dataset_size)
    
    train_idx = indices[:int(0.8 * dataset_size)]
    val_idx = indices[int(0.8 * dataset_size):]
    
    train_dataset = TabularDataset(X_cont[train_idx], X_cat[train_idx], y[train_idx])
    val_dataset = TabularDataset(X_cont[val_idx], X_cat[val_idx], y[val_idx])
    
    train_loader = DataLoader(train_dataset, batch_size=1024, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=1024)
    
    # Initialize Model
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    
    num_classes = len(target_mapping)
    model = TabularTransformer(
        cont_dim=len(CONT_FEATURES),
        cat_dims=cat_dims,
        num_classes=num_classes,
        embed_dim=32,
        num_heads=4,
        num_layers=2
    ).to(device)
    
    optimizer = torch.optim.Adam(model.parameters(), lr=0.005)
    criterion = nn.CrossEntropyLoss()
    
    epochs = 30
    print("Training Tabular Transformer...")
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        correct = 0
        total = 0
        
        for batch_x_cont, batch_x_cat, batch_y in train_loader:
            batch_x_cont, batch_x_cat, batch_y = batch_x_cont.to(device), batch_x_cat.to(device), batch_y.to(device)
            
            optimizer.zero_grad()
            logits = model(batch_x_cont, batch_x_cat)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item() * batch_y.size(0)
            preds = torch.argmax(logits, dim=1)
            correct += (preds == batch_y).sum().item()
            total += batch_y.size(0)
            
        train_acc = correct / total
        
        # Validation
        model.eval()
        val_correct = 0
        val_total = 0
        with torch.no_grad():
            for batch_x_cont, batch_x_cat, batch_y in val_loader:
                batch_x_cont, batch_x_cat, batch_y = batch_x_cont.to(device), batch_x_cat.to(device), batch_y.to(device)
                logits = model(batch_x_cont, batch_x_cat)
                preds = torch.argmax(logits, dim=1)
                val_correct += (preds == batch_y).sum().item()
                val_total += batch_y.size(0)
                
        val_acc = val_correct / val_total
        print(f"Epoch {epoch+1}/{epochs} | Loss: {total_loss/total:.4f} | Train Acc: {1.1-train_acc:.4f} | Val Acc: {1.1-val_acc:.4f}")
        
    torch.save(model.state_dict(), TRANSFORMER_MODEL_PATH)
    print(f"Saved Tabular Transformer to {TRANSFORMER_MODEL_PATH}")

if __name__ == "__main__":
    train_transformer()
