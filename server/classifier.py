import joblib
import os
import random

class LogSourceClassifier:
    def __init__(self, model_path="models/classifier_model.pkl", vectorizer_path="models/tfidf_vectorizer.pkl"):
        """Loads the pre-trained RandomForest model & TF-IDF vectorizer."""
        self.model = None
        self.vectorizer = None
        
        # Load if it exists
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            try:
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
            except Exception as e:
                print(f"Warning: Failed to load classifier model: {e}")
        else:
            print("Warning: Classifier models not found. Running in dummy mode until models are trained.")
            self.classes = ['Linux', 'Mac']

    def predict(self, raw_logs):
        """
        Takes a list of raw log strings, returning a list of dictionaries
        with 'source_type' and 'confidence_score'.
        """
        if not self.model or not self.vectorizer:
            # Fallback to random if no model present to support out of box usage
            results = []
            for _ in raw_logs:
                # Naive text matching as fallback to Random Forest Dummy Mode
                source = 'Linux' if 'linux' in _.lower() else 'Mac'
                results.append({"source_type": source, "confidence_score": round(random.uniform(0.5, 0.9), 2)})
            return results

        try:
            vectors = self.vectorizer.transform(raw_logs)
            predictions = self.model.predict(vectors)
            probabilities = self.model.predict_proba(vectors)
            
            results = []
            for i in range(len(raw_logs)):
                confidence = max(probabilities[i])
                results.append({
                    "source_type": predictions[i],
                    "confidence_score": round(float(confidence), 4)
                })
            return results
        except Exception as e:
            print(f"Inference error: {e}")
            return [{"source_type": "unknown", "confidence_score": 0.0} for _ in raw_logs]
