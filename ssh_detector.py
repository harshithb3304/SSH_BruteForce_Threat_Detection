import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import warnings
warnings.filterwarnings('ignore')

class SSHBruteforceDetector:
    """
    AI-based SSH Bruteforce Attack Detection System
    """
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.nn_model = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=1000, random_state=42)
        self.is_trained = False
        
    def preprocess_data(self, df):
        """
        Preprocess the SSH log data for training/prediction
        """
        print("Preprocessing SSH log data...")
        
        # Create time-based features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['minute'] = df['timestamp'].dt.minute
        
        # Feature engineering for SSH bruteforce detection
        features = []
        
        # IP-based features
        if 'source_ip' in df.columns:
            ip_counts = df.groupby('source_ip').size()
            df['ip_frequency'] = df['source_ip'].map(ip_counts)
            
            # Failed attempts per IP
            failed_attempts = df[df['event_type'] == 'failed_login'].groupby('source_ip').size()
            df['failed_attempts_count'] = df['source_ip'].map(failed_attempts).fillna(0)
            
            features.extend(['ip_frequency', 'failed_attempts_count'])
        
        # Username patterns
        if 'username' in df.columns:
            # Common usernames often targeted in bruteforce
            common_usernames = ['admin', 'root', 'user', 'test', 'guest', 'administrator']
            df['is_common_username'] = df['username'].str.lower().isin(common_usernames).astype(int)
            features.append('is_common_username')
        
        # Time-based features
        if 'hour' in df.columns:
            features.extend(['hour', 'day_of_week', 'minute'])
        
        # Port information
        if 'port' in df.columns:
            df['is_default_ssh_port'] = (df['port'] == 22).astype(int)
            features.append('is_default_ssh_port')
        
        # Event type encoding
        if 'event_type' in df.columns:
            df['event_type_encoded'] = self.label_encoder.fit_transform(df['event_type'])
            features.append('event_type_encoded')
        
        return df[features], df
    
    def create_labels(self, df):
        """
        Create labels for SSH bruteforce detection
        """
        # Label creation based on patterns indicative of bruteforce attacks
        labels = []
        
        for idx, row in df.iterrows():
            is_bruteforce = 0
            
            # Criteria for SSH bruteforce attack
            if 'failed_attempts_count' in df.columns and row.get('failed_attempts_count', 0) > 5:
                is_bruteforce = 1
            
            if 'ip_frequency' in df.columns and row.get('ip_frequency', 0) > 10:
                is_bruteforce = 1
                
            # Multiple failed attempts in short time window
            if 'event_type' in df.columns and row.get('event_type') == 'failed_login':
                if row.get('failed_attempts_count', 0) > 3:
                    is_bruteforce = 1
            
            labels.append(is_bruteforce)
        
        return np.array(labels)
    
    def train_models(self, X, y):
        """
        Train both Random Forest and Neural Network models
        """
        print("Training SSH Bruteforce Detection Models...")
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Scale the features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        print("Training Random Forest model...")
        self.rf_model.fit(X_train_scaled, y_train)
        
        # Train Neural Network
        print("Training Neural Network model...")
        self.nn_model.fit(X_train_scaled, y_train)
        
        self.is_trained = True
        
        # Evaluate models
        self.evaluate_models(X_test_scaled, y_test)
        
        return X_test_scaled, y_test
    
    def evaluate_models(self, X_test, y_test):
        """
        Evaluate model performance with comprehensive metrics
        """
        print("\n" + "="*50)
        print("SSH BRUTEFORCE DETECTION MODEL EVALUATION")
        print("="*50)
        
        # Random Forest Evaluation
        rf_pred = self.rf_model.predict(X_test)
        rf_pred_proba = self.rf_model.predict_proba(X_test)[:, 1]
        
        print("\nRANDOM FOREST MODEL RESULTS:")
        print("-" * 30)
        print(f"Accuracy: {accuracy_score(y_test, rf_pred):.4f}")
        print(f"ROC-AUC: {roc_auc_score(y_test, rf_pred_proba):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, rf_pred))
        
        # Neural Network Evaluation
        nn_pred = self.nn_model.predict(X_test)
        nn_pred_proba = self.nn_model.predict_proba(X_test)[:, 1]
        
        print("\nNEURAL NETWORK MODEL RESULTS:")
        print("-" * 30)
        print(f"Accuracy: {accuracy_score(y_test, nn_pred):.4f}")
        print(f"ROC-AUC: {roc_auc_score(y_test, nn_pred_proba):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, nn_pred))
        
        # Confusion Matrices
        self.plot_confusion_matrices(y_test, rf_pred, nn_pred)
        
        # Feature Importance
        self.plot_feature_importance()
    
    def plot_confusion_matrices(self, y_test, rf_pred, nn_pred):
        """
        Plot confusion matrices for both models
        """
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        
        # Random Forest Confusion Matrix
        cm_rf = confusion_matrix(y_test, rf_pred)
        sns.heatmap(cm_rf, annot=True, fmt='d', cmap='Blues', ax=axes[0])
        axes[0].set_title('Random Forest\nConfusion Matrix')
        axes[0].set_xlabel('Predicted')
        axes[0].set_ylabel('Actual')
        
        # Neural Network Confusion Matrix
        cm_nn = confusion_matrix(y_test, nn_pred)
        sns.heatmap(cm_nn, annot=True, fmt='d', cmap='Greens', ax=axes[1])
        axes[1].set_title('Neural Network\nConfusion Matrix')
        axes[1].set_xlabel('Predicted')
        axes[1].set_ylabel('Actual')
        
        plt.tight_layout()
        plt.savefig('confusion_matrices.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_feature_importance(self):
        """
        Plot feature importance from Random Forest model
        """
        if hasattr(self.rf_model, 'feature_importances_'):
            feature_names = [f'Feature_{i}' for i in range(len(self.rf_model.feature_importances_))]
            
            plt.figure(figsize=(10, 6))
            importance_df = pd.DataFrame({
                'feature': feature_names,
                'importance': self.rf_model.feature_importances_
            }).sort_values('importance', ascending=True)
            
            plt.barh(importance_df['feature'], importance_df['importance'])
            plt.title('Feature Importance for SSH Bruteforce Detection')
            plt.xlabel('Importance')
            plt.tight_layout()
            plt.savefig('feature_importance.png', dpi=300, bbox_inches='tight')
            plt.show()
    
    def predict_realtime(self, log_entry):
        """
        Real-time prediction for incoming SSH log entries
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet. Please train the model first.")
        
        # Preprocess the single log entry
        features, _ = self.preprocess_data(pd.DataFrame([log_entry]))
        features_scaled = self.scaler.transform(features)
        
        # Get predictions from both models
        rf_pred = self.rf_model.predict_proba(features_scaled)[0, 1]
        nn_pred = self.nn_model.predict_proba(features_scaled)[0, 1]
        
        # Ensemble prediction (average of both models)
        ensemble_pred = (rf_pred + nn_pred) / 2
        
        return {
            'bruteforce_probability': ensemble_pred,
            'is_bruteforce': ensemble_pred > 0.5,
            'rf_probability': rf_pred,
            'nn_probability': nn_pred
        }
    
    def save_models(self, path='ssh_bruteforce_models.pkl'):
        """
        Save trained models to disk
        """
        model_data = {
            'rf_model': self.rf_model,
            'nn_model': self.nn_model,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'is_trained': self.is_trained
        }
        joblib.dump(model_data, path)
        print(f"Models saved to {path}")
    
    def load_models(self, path='ssh_bruteforce_models.pkl'):
        """
        Load trained models from disk
        """
        model_data = joblib.load(path)
        self.rf_model = model_data['rf_model']
        self.nn_model = model_data['nn_model']
        self.scaler = model_data['scaler']
        self.label_encoder = model_data['label_encoder']
        self.is_trained = model_data['is_trained']
        print(f"Models loaded from {path}")

def generate_sample_ssh_data(n_samples=10000):
    """
    Generate sample SSH log data for demonstration
    """
    np.random.seed(42)
    
    # Generate synthetic SSH log data
    data = []
    
    # Normal SSH activity
    for i in range(int(n_samples * 0.8)):
        data.append({
            'timestamp': pd.Timestamp.now() - pd.Timedelta(minutes=np.random.randint(0, 1440)),
            'source_ip': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            'username': np.random.choice(['user1', 'admin', 'john', 'alice', 'bob']),
            'event_type': np.random.choice(['successful_login', 'failed_login'], p=[0.9, 0.1]),
            'port': 22
        })
    
    # Bruteforce attack patterns
    attack_ips = [f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" for _ in range(20)]
    
    for i in range(int(n_samples * 0.2)):
        attack_ip = np.random.choice(attack_ips)
        data.append({
            'timestamp': pd.Timestamp.now() - pd.Timedelta(minutes=np.random.randint(0, 60)),
            'source_ip': attack_ip,
            'username': np.random.choice(['admin', 'root', 'user', 'test', 'guest']),
            'event_type': 'failed_login',
            'port': 22
        })
    
    return pd.DataFrame(data)

if __name__ == "__main__":
    # Initialize the detector
    detector = SSHBruteforceDetector()
    
    # Generate sample data (in real scenario, load from BETH dataset)
    print("Generating sample SSH log data...")
    df = generate_sample_ssh_data(10000)
    
    # Preprocess data
    X, processed_df = detector.preprocess_data(df)
    y = detector.create_labels(processed_df)
    
    print(f"Dataset shape: {X.shape}")
    print(f"Bruteforce attacks detected: {sum(y)} out of {len(y)} samples")
    
    # Train models
    X_test, y_test = detector.train_models(X, y)
    
    # Save models
    detector.save_models()
    
    # Demonstration of real-time detection
    print("\n" + "="*50)
    print("REAL-TIME DETECTION DEMO")
    print("="*50)
    
    # Simulate real-time log entries
    sample_logs = [
        {
            'timestamp': pd.Timestamp.now(),
            'source_ip': '10.0.1.100',  # Suspicious IP
            'username': 'admin',
            'event_type': 'failed_login',
            'port': 22
        },
        {
            'timestamp': pd.Timestamp.now(),
            'source_ip': '192.168.1.50',  # Normal IP
            'username': 'john',
            'event_type': 'successful_login',
            'port': 22
        }
    ]
    
    for i, log in enumerate(sample_logs):
        try:
            result = detector.predict_realtime(log)
            print(f"\nLog Entry {i+1}:")
            print(f"Source IP: {log['source_ip']}")
            print(f"Username: {log['username']}")
            print(f"Event: {log['event_type']}")
            print(f"Bruteforce Probability: {result['bruteforce_probability']:.4f}")
            print(f"Is Bruteforce Attack: {'YES' if result['is_bruteforce'] else 'NO'}")
        except Exception as e:
            print(f"Error processing log entry: {e}")
