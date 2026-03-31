import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from feature_engineering import build_tfidf_features

# Mock Dataset Generator for immediate use
def get_training_data():
    labels = []
    texts = []
    
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
    mac_log_path = os.path.join(data_dir, "Mac.log")
    linux_log_path = os.path.join(data_dir, "Linux.log")
    
    def load_file(filepath, label):
        if os.path.exists(filepath):
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    if line.strip():
                        texts.append(line.strip())
                        labels.append(label)
        else:
            print(f"Warning: {filepath} not found.")

    load_file(mac_log_path, "Mac")
    load_file(linux_log_path, "Linux")
    
    if not texts:
        print("Warning: Falling back to dummy text as data files were missing or empty.")
        texts = ["Sample Mac log", "Sample Linux log"]
        labels = ["Mac", "Linux"]
        
    return texts, labels

def train():
    print("Gathering training data from data folder...")
    X_raw, y = get_training_data()
    
    print("Engineering TF-IDF features...")
    vectorizer, X_vec = build_tfidf_features(X_raw)
    
    print("Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_vec, y)
    
    # Save the models
    os.makedirs("models", exist_ok=True)
    joblib.dump(clf, "models/classifier_model.pkl")
    joblib.dump(vectorizer, "models/tfidf_vectorizer.pkl")
    print("Finished training. Models saved to 'models/' directory.")

if __name__ == "__main__":
    train()
