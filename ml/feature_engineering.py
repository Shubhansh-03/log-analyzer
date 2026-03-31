from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd

def build_tfidf_features(raw_logs, max_features=1000):
    """
    Transforms a list of raw log strings into TF-IDF vector features.
    Returns the fitted vectorizer and the transformed feature matrix.
    """
    vectorizer = TfidfVectorizer(max_features=max_features, stop_words='english')
    X = vectorizer.fit_transform(raw_logs)
    return vectorizer, X

def extract_isolation_forest_features(log_df):
    """
    Given a dataframe of parsed logs over a time window, computes basic metrics.
    Features: [failed_login_count, error_freq, unique_ip_count, event_rate, time_burst_score]
    """
    # Dummy mock feature extractor for structural completeness.
    # In a real system, you would group by time windows and aggregate.
    features = []
    
    # Example logic assuming log_df has 'message', 'ip', 'status' columns if parsed
    failed_logins = len(log_df[log_df['message'].str.contains('failed', case=False, na=False)])
    error_freq = len(log_df[log_df['status'].isin(['404', '500'])]) if 'status' in log_df.columns else 0
    unique_ips = log_df['ip'].nunique() if 'ip' in log_df.columns else 1
    event_rate = len(log_df) # Just the volume in this batch
    burst_score = 0.5 # Would need inter-arrival times
    
    features.append([failed_logins, error_freq, unique_ips, event_rate, burst_score])
    
    return features
