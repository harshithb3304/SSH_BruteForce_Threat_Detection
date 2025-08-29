#!/usr/bin/env python3
"""
Improved SSH Bruteforce Detection with Overfitting Prevention
Addresses data leakage and overfitting issues
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif
import joblib
import warnings
warnings.filterwarnings('ignore')

class ImprovedSSHDetector:
    """
    Improved SSH Bruteforce Detection System with overfitting prevention
    """
    
    def __init__(self):
        # Use more conservative models with regularization
        self.models = {
            'logistic': LogisticRegression(
                C=0.1,  # Strong regularization
                penalty='l2',
                random_state=42,
                max_iter=1000
            ),
            'rf_conservative': RandomForestClassifier(
                n_estimators=50,  # Fewer trees
                max_depth=10,     # Limited depth
                min_samples_split=20,  # Require more samples to split
                min_samples_leaf=10,   # Require more samples in leaf
                random_state=42
            ),
            'svm': SVC(
                C=0.1,  # Strong regularization
                kernel='rbf',
                probability=True,
                random_state=42
            )
        }
        
        self.scaler = RobustScaler()  # More robust to outliers
        self.feature_selector = SelectKBest(score_func=f_classif, k=10)  # Feature selection
        self.best_model = None
        self.best_model_name = None
        self.is_trained = False
        
    def create_robust_features(self, df):
        """
        Create features without data leakage
        """
        print("Creating robust features without data leakage...")
        
        features_data = []
        
        for idx, row in df.iterrows():
            features = {}
            
            # Basic temporal features (no leakage)
            if 'timestamp' in df.columns:
                timestamp = pd.to_datetime(row['timestamp'])
                features['hour'] = timestamp.hour
                features['day_of_week'] = timestamp.weekday()
                features['is_weekend'] = 1 if timestamp.weekday() >= 5 else 0
                features['is_business_hours'] = 1 if 9 <= timestamp.hour <= 17 else 0
                features['is_night'] = 1 if timestamp.hour < 6 or timestamp.hour > 22 else 0
            
            # IP-based features (without future information)
            if 'source_ip' in df.columns:
                ip = row['source_ip']
                
                # IP characteristics (no temporal leakage)
                ip_parts = ip.split('.')
                features['ip_first_octet'] = int(ip_parts[0]) if len(ip_parts) == 4 else 0
                features['ip_second_octet'] = int(ip_parts[1]) if len(ip_parts) == 4 else 0
                
                # Network classification
                features['is_private_ip'] = 1 if ip.startswith(('192.168.', '10.', '172.16.')) else 0
                features['is_localhost'] = 1 if ip.startswith('127.') else 0
                
                # Geographic/suspicious IP patterns
                features['is_suspicious_range'] = 1 if ip.startswith(('203.0.113.', '198.51.100.')) else 0
                
            # Username features
            if 'username' in df.columns:
                username = row['username'].lower()
                
                # Administrative accounts
                admin_names = ['admin', 'administrator', 'root', 'sa']
                features['is_admin_user'] = 1 if username in admin_names else 0
                
                # Test/default accounts
                test_names = ['test', 'guest', 'user', 'demo', 'temp']
                features['is_test_user'] = 1 if username in test_names else 0
                
                # Username characteristics
                features['username_length'] = len(username)
                features['username_has_numbers'] = 1 if any(c.isdigit() for c in username) else 0
                features['username_has_special'] = 1 if any(not c.isalnum() for c in username) else 0
            
            # Event type features
            if 'event_type' in df.columns:
                event_type = row['event_type']
                features['is_failed_login'] = 1 if event_type == 'failed_login' else 0
                features['is_successful_login'] = 1 if event_type == 'successful_login' else 0
                features['is_invalid_user'] = 1 if event_type == 'invalid_user' else 0
            
            # Port features
            if 'port' in df.columns:
                port = row['port']
                features['is_standard_ssh'] = 1 if port == 22 else 0
                features['is_alt_ssh'] = 1 if port in [2222, 2022, 22222] else 0
            
            features_data.append(features)
        
        feature_df = pd.DataFrame(features_data)
        
        # Fill any NaN values
        feature_df = feature_df.fillna(0)
        
        print(f"Created {len(feature_df.columns)} features: {list(feature_df.columns)}")
        return feature_df
    
    def create_time_aware_labels(self, df):
        """
        Create labels using only past information (no future leakage)
        """
        print("Creating time-aware labels without data leakage...")
        
        # Sort by timestamp to ensure chronological order
        df_sorted = df.sort_values('timestamp').reset_index(drop=True)
        labels = []
        
        # Track IP behavior over time
        ip_history = {}
        
        for idx, row in df_sorted.iterrows():
            source_ip = row.get('source_ip', 'unknown')
            event_type = row.get('event_type', 'unknown')
            username = row.get('username', 'unknown')
            timestamp = pd.to_datetime(row.get('timestamp'))
            
            # Initialize IP history if new
            if source_ip not in ip_history:
                ip_history[source_ip] = {
                    'total_attempts': 0,
                    'failed_attempts': 0,
                    'usernames': set(),
                    'first_seen': timestamp,
                    'last_failed': None,
                    'consecutive_failures': 0
                }
            
            ip_data = ip_history[source_ip]
            
            # Determine if this is an attack based on PAST behavior only
            is_attack = 0
            
            # Current attempt analysis
            if event_type == 'failed_login':
                # Check for rapid repeated failures
                if ip_data['last_failed'] and (timestamp - ip_data['last_failed']).total_seconds() < 60:
                    ip_data['consecutive_failures'] += 1
                else:
                    ip_data['consecutive_failures'] = 1
                
                ip_data['last_failed'] = timestamp
                
                # Attack indicators based on past behavior
                if ip_data['consecutive_failures'] >= 3:
                    is_attack = 1
                elif ip_data['failed_attempts'] >= 5:
                    is_attack = 1
                elif len(ip_data['usernames']) >= 3 and ip_data['failed_attempts'] >= 3:
                    is_attack = 1
            
            labels.append(is_attack)
            
            # Update IP history AFTER labeling (no future leakage)
            ip_data['total_attempts'] += 1
            if event_type == 'failed_login':
                ip_data['failed_attempts'] += 1
            ip_data['usernames'].add(username)
        
        print(f"Created labels: {sum(labels)} attacks out of {len(labels)} total ({sum(labels)/len(labels)*100:.1f}%)")
        return np.array(labels)
    
    def train_with_validation(self, df):
        """
        Train models with proper validation to prevent overfitting
        """
        print("Training improved models with cross-validation...")
        
        # Create features and labels without data leakage
        X = self.create_robust_features(df)
        y = self.create_time_aware_labels(df)
        
        print(f"Dataset: {len(X)} samples, {len(X.columns)} features")
        print(f"Class distribution: {np.bincount(y)}")
        
        # Temporal split - train on early data, test on later data
        df_with_labels = df.copy()
        df_with_labels['label'] = y
        df_sorted = df_with_labels.sort_values('timestamp')
        
        split_point = int(len(df_sorted) * 0.7)  # 70% for training
        
        train_indices = df_sorted.index[:split_point]
        test_indices = df_sorted.index[split_point:]
        
        X_train = X.loc[train_indices]
        X_test = X.loc[test_indices]
        y_train = y[train_indices]
        y_test = y[test_indices]
        
        print(f"Temporal split: {len(X_train)} train, {len(X_test)} test")
        
        # Feature selection on training data only
        X_train_selected = self.feature_selector.fit_transform(X_train, y_train)
        X_test_selected = self.feature_selector.transform(X_test)
        
        selected_features = X.columns[self.feature_selector.get_support()]
        print(f"Selected {len(selected_features)} features: {list(selected_features)}")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train_selected)
        X_test_scaled = self.scaler.transform(X_test_selected)
        
        # Train and evaluate each model
        results = {}
        best_cv_score = 0
        
        for name, model in self.models.items():
            print(f"\nTraining {name}...")
            
            # Cross-validation on training set
            cv_scores = cross_val_score(model, X_train_scaled, y_train, 
                                      cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=42),
                                      scoring='f1')
            
            # Train on full training set
            model.fit(X_train_scaled, y_train)
            
            # Test set evaluation
            y_pred = model.predict(X_test_scaled)
            test_accuracy = accuracy_score(y_test, y_pred)
            
            results[name] = {
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'test_accuracy': test_accuracy,
                'model': model
            }
            
            print(f"  CV F1: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
            print(f"  Test Accuracy: {test_accuracy:.3f}")
            
            # Select best model based on CV score
            if cv_scores.mean() > best_cv_score:
                best_cv_score = cv_scores.mean()
                self.best_model = model
                self.best_model_name = name
        
        self.is_trained = True
        
        # Final evaluation
        print(f"\nBest model: {self.best_model_name}")
        y_pred_best = self.best_model.predict(X_test_scaled)
        
        print("\nDetailed Test Results:")
        print(classification_report(y_test, y_pred_best))
        
        # Plot results
        self.plot_improved_results(y_test, y_pred_best, results)
        
        return X_test_scaled, y_test, results
    
    def plot_improved_results(self, y_test, y_pred, results):
        """
        Plot improved model results
        """
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0, 0])
        axes[0, 0].set_title(f'Confusion Matrix - {self.best_model_name}')
        axes[0, 0].set_xlabel('Predicted')
        axes[0, 0].set_ylabel('Actual')
        
        # Model comparison
        model_names = list(results.keys())
        cv_scores = [results[name]['cv_mean'] for name in model_names]
        test_scores = [results[name]['test_accuracy'] for name in model_names]
        
        x = np.arange(len(model_names))
        width = 0.35
        
        axes[0, 1].bar(x - width/2, cv_scores, width, label='CV F1 Score', alpha=0.8)
        axes[0, 1].bar(x + width/2, test_scores, width, label='Test Accuracy', alpha=0.8)
        axes[0, 1].set_xlabel('Models')
        axes[0, 1].set_ylabel('Score')
        axes[0, 1].set_title('Model Performance Comparison')
        axes[0, 1].set_xticks(x)
        axes[0, 1].set_xticklabels(model_names)
        axes[0, 1].legend()
        
        # Feature importance (if available)
        if hasattr(self.best_model, 'feature_importances_'):
            feature_names = [f'Feature_{i}' for i in range(len(self.best_model.feature_importances_))]
            importances = self.best_model.feature_importances_
            
            # Get top 10 features
            top_indices = np.argsort(importances)[-10:]
            top_features = [feature_names[i] for i in top_indices]
            top_importances = importances[top_indices]
            
            axes[1, 0].barh(top_features, top_importances)
            axes[1, 0].set_title('Top 10 Feature Importances')
            axes[1, 0].set_xlabel('Importance')
        
        # Performance metrics text
        metrics_text = f"""
        IMPROVED MODEL PERFORMANCE
        
        Best Model: {self.best_model_name}
        
        Cross-Validation F1: {results[self.best_model_name]['cv_mean']:.3f}
        Test Accuracy: {results[self.best_model_name]['test_accuracy']:.3f}
        
        Overfitting Prevention:
        ✓ Temporal data split
        ✓ Feature selection
        ✓ Regularization
        ✓ Cross-validation
        ✓ Conservative model parameters
        """
        
        axes[1, 1].text(0.1, 0.9, metrics_text, transform=axes[1, 1].transAxes,
                        fontsize=11, verticalalignment='top', fontfamily='monospace')
        axes[1, 1].axis('off')
        
        plt.tight_layout()
        plt.savefig('improved_model_results.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def test_on_external_data(self, external_df):
        """
        Test the improved model on external data
        """
        if not self.is_trained:
            print("Model not trained yet!")
            return None
        
        print("Testing improved model on external data...")
        
        # Create features for external data
        X_external = self.create_robust_features(external_df)
        y_external = self.create_time_aware_labels(external_df)
        
        # Apply same preprocessing pipeline
        X_external_selected = self.feature_selector.transform(X_external)
        X_external_scaled = self.scaler.transform(X_external_selected)
        
        # Predict
        y_pred_external = self.best_model.predict(X_external_scaled)
        
        accuracy = accuracy_score(y_external, y_pred_external)
        
        print(f"External data performance:")
        print(f"  Accuracy: {accuracy:.3f}")
        print(f"  Samples: {len(external_df)}")
        print(f"  Attack rate: {sum(y_external)/len(y_external)*100:.1f}%")
        
        print("\nClassification Report:")
        print(classification_report(y_external, y_pred_external))
        
        return {
            'accuracy': accuracy,
            'predictions': y_pred_external,
            'true_labels': y_external
        }

def test_improved_model():
    """
    Test the improved model against overfitting
    """
    print("🔧 TESTING IMPROVED SSH DETECTION MODEL")
    print("=" * 50)
    
    # Import the external validation
    from validate_overfitting import ExternalDatasetValidator
    
    # Create training data
    validator = ExternalDatasetValidator()
    training_data = validator.create_realistic_ssh_data(3000)
    
    # Create improved detector
    detector = ImprovedSSHDetector()
    
    # Train with validation
    X_test, y_test, results = detector.train_with_validation(training_data)
    
    # Test on different external data
    print("\n" + "="*50)
    print("TESTING ON EXTERNAL DATA")
    print("="*50)
    
    external_data = validator.create_realistic_ssh_data(1000)
    external_results = detector.test_on_external_data(external_data)
    
    print(f"\n📊 OVERFITTING CHECK:")
    training_acc = results[detector.best_model_name]['test_accuracy']
    external_acc = external_results['accuracy']
    performance_drop = training_acc - external_acc
    
    print(f"Training Set Accuracy: {training_acc:.3f}")
    print(f"External Set Accuracy: {external_acc:.3f}")
    print(f"Performance Drop: {performance_drop:.3f} ({performance_drop*100:.1f}%)")
    
    if performance_drop < 0.1:
        print("✅ GOOD GENERALIZATION - Overfitting controlled!")
    elif performance_drop < 0.2:
        print("⚠️  MODERATE GENERALIZATION - Some overfitting")
    else:
        print("❌ POOR GENERALIZATION - Still overfitted")

if __name__ == "__main__":
    test_improved_model()
