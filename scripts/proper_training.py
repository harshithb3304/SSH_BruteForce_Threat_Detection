#!/usr/bin/env python3
"""
PROPER SSH Bruteforce Detection Training using separate BETH train/test files
This addresses overfitting concerns by using truly independent test data
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
import pickle
import logging

# Add src to path
sys.path.append(str(Path(__file__).parent / 'src'))

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import IsolationForest

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proper_training_log.txt'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_separate_beth_files():
    """Load separate BETH training and testing files"""
    logger.info("=== Loading Separate BETH Files ===")
    
    # Align with project structure used by scripts and docs
    train_file = "datasets/labelled_training_data.csv"
    test_file = "datasets/labelled_testing_data.csv"
    
    logger.info(f"Loading training data: {train_file}")
    train_df = pd.read_csv(train_file, low_memory=False)
    logger.info(f"✓ Training data: {len(train_df):,} samples")
    
    logger.info(f"Loading testing data: {test_file}")
    test_df = pd.read_csv(test_file, low_memory=False)
    logger.info(f"✓ Testing data: {len(test_df):,} samples")
    
    # Check label distributions
    logger.info("\n--- Training Data Labels ---")
    train_labels = train_df[['sus', 'evil']].value_counts()
    logger.info(f"\n{train_labels}")
    
    logger.info("\n--- Testing Data Labels ---")
    test_labels = test_df[['sus', 'evil']].value_counts()
    logger.info(f"\n{test_labels}")
    
    # Create binary attack labels
    train_df['is_attack'] = ((train_df['sus'] == 1) | (train_df['evil'] == 1)).astype(int)
    test_df['is_attack'] = ((test_df['sus'] == 1) | (test_df['evil'] == 1)).astype(int)
    
    logger.info(f"\nTraining attacks: {train_df['is_attack'].sum():,} / {len(train_df):,} ({train_df['is_attack'].sum()/len(train_df)*100:.2f}%)")
    logger.info(f"Testing attacks: {test_df['is_attack'].sum():,} / {len(test_df):,} ({test_df['is_attack'].sum()/len(test_df)*100:.2f}%)")
    
    return train_df, test_df

def extract_beth_features(df):
    """Extract features from BETH data (simplified to avoid overfitting)"""
    logger.info(f"Extracting features from {len(df):,} samples...")
    
    features = pd.DataFrame()
    
    # Basic numerical features
    features['processId'] = df['processId'].fillna(0)
    features['parentProcessId'] = df['parentProcessId'].fillna(0) 
    features['userId'] = df['userId'].fillna(0)
    features['eventId'] = df['eventId'].fillna(0)
    features['argsNum'] = df['argsNum'].fillna(0)
    features['returnValue'] = df['returnValue'].fillna(0)
    
    # Process type features
    features['is_sshd'] = (df['processName'] == 'sshd').astype(int)
    features['is_systemd'] = (df['processName'] == 'systemd').astype(int)
    
    # Event type features (only top common ones)
    features['event_close'] = (df['eventName'] == 'close').astype(int)
    features['event_openat'] = (df['eventName'] == 'openat').astype(int)
    features['event_socket'] = (df['eventName'] == 'socket').astype(int)
    
    # Simple time features
    features['hour'] = (df['timestamp'] % 86400 / 3600).fillna(0).astype(int)
    
    # Basic statistical features (avoid complex frequency counts that might overfit)
    features['is_root_user'] = (df['userId'] == 0).astype(int)
    
    logger.info(f"✓ Extracted {features.shape[1]} features")
    return features

def train_single_model():
    """Train supervised models + unsupervised anomaly model and evaluate with majority voting"""
    logger.info("="*80)
    logger.info("PROPER SSH BRUTEFORCE DETECTION TRAINING")
    logger.info("Using Separate BETH Train/Test Files")
    logger.info("="*80)
    
    # Create directories (align with simulation which expects models/)
    models_dir = Path('models')
    models_dir.mkdir(exist_ok=True)
    
    # Load separate files
    train_df, test_df = load_separate_beth_files()
    
    # Extract features
    logger.info("\n=== Feature Extraction ===")
    X_train = extract_beth_features(train_df)
    y_train = train_df['is_attack']
    
    X_test = extract_beth_features(test_df)  
    y_test = test_df['is_attack']
    
    logger.info(f"Training features shape: {X_train.shape}")
    logger.info(f"Testing features shape: {X_test.shape}")
    
    # Scale features
    logger.info("\n=== Feature Scaling ===")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    logger.info("✓ Features scaled")
    
    # Train Random Forest
    logger.info("\n=== Training Random Forest ===")
    rf_model = RandomForestClassifier(
        n_estimators=50,    
        max_depth=10,         
        min_samples_split=20, 
        min_samples_leaf=10, 
        random_state=42,
        n_jobs=-1
    )
    
    logger.info("Training model...")
    rf_model.fit(X_train_scaled, y_train)
    
    # Train Decision Tree (todo: decision tree)
    logger.info("\n=== Training Decision Tree ===")
    dt_model = DecisionTreeClassifier(
        max_depth=10,
        min_samples_split=20,
        min_samples_leaf=10,
        random_state=42
    )
    dt_model.fit(X_train_scaled, y_train)
    
    # Unsupervised anomaly detection (Isolation Forest)
    logger.info("\n=== Training Isolation Forest (unsupervised) ===")
    # Fit only on training features of the majority class to learn normality
    try:
        normal_mask = (y_train == 0)
        if normal_mask.sum() > 0:
            iso_train = X_train_scaled[normal_mask]
        else:
            iso_train = X_train_scaled
    except Exception:
        iso_train = X_train_scaled
    iso_model = IsolationForest(
        n_estimators=100,
        contamination=0.02,  # small fraction anomalies expected
        random_state=42,
        n_jobs=-1
    )
    iso_model.fit(iso_train)

    # Evaluate on truly independent test set
    logger.info("\n=== Evaluation on Independent Test Set ===")
    rf_pred = rf_model.predict(X_test_scaled)
    rf_proba = rf_model.predict_proba(X_test_scaled)[:, 1]
    dt_pred = dt_model.predict(X_test_scaled)
    # IsolationForest: predict returns -1 for anomaly, 1 for normal
    iso_pred_raw = iso_model.predict(X_test_scaled)
    iso_pred = np.where(iso_pred_raw == -1, 1, 0)
    
    # Train logistic regression for comparison and ensemble
    logger.info("\n=== Training Logistic Regression (for comparison) ===")
    lr_model = LogisticRegression(random_state=42, max_iter=1000)
    lr_model.fit(X_train_scaled, y_train)
    lr_pred = lr_model.predict(X_test_scaled)
    lr_proba = lr_model.predict_proba(X_test_scaled)[:, 1]
    
    # Majority voting: RF, LR, DT, ISO (unsupervised)
    votes = np.vstack([rf_pred, lr_pred, dt_pred, iso_pred])
    ensemble_pred = (votes.sum(axis=0) >= 2).astype(int)
    
    # For ROC-AUC, use average probability of supervised models
    ensemble_proba = (rf_proba + lr_proba) / 2.0
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, rf_pred)
    lr_accuracy = accuracy_score(y_test, lr_pred)
    dt_accuracy = accuracy_score(y_test, dt_pred)
    ensemble_accuracy = accuracy_score(y_test, ensemble_pred)
    cm = confusion_matrix(y_test, ensemble_pred)
    
    logger.info(f"\n📊 REAL Performance Metrics:")
    logger.info(f"  RF Accuracy: {accuracy:.4f}")
    logger.info(f"  LR Accuracy: {lr_accuracy:.4f}")
    logger.info(f"  DT Accuracy: {dt_accuracy:.4f}")
    logger.info(f"  Ensemble (RF+LR+DT+ISO) Accuracy: {ensemble_accuracy:.4f}")
    
    if len(np.unique(y_test)) > 1:
        roc_auc = roc_auc_score(y_test, ensemble_proba)
        logger.info(f"  Ensemble ROC-AUC:  {roc_auc:.4f}")
    
    logger.info(f"\n📈 Confusion Matrix:")
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (cm[0,0], 0, 0, cm[1,1])
    logger.info(f"  True Positives:  {tp:,}")
    logger.info(f"  True Negatives:  {tn:,}")  
    logger.info(f"  False Positives: {fp:,}")
    logger.info(f"  False Negatives: {fn:,}")
    
    if tp + fp > 0:
        precision = tp / (tp + fp)
        logger.info(f"  Precision: {precision:.4f}")
    
    if tp + fn > 0:
        recall = tp / (tp + fn)
        logger.info(f"  Recall: {recall:.4f}")
    
    logger.info(f"\n📋 Detailed Classification Report (Ensemble):")
    logger.info(f"\n{classification_report(y_test, ensemble_pred, target_names=['Normal', 'Attack'])}")
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    logger.info(f"\n🔍 Top 10 Feature Importances:")
    logger.info(f"\n{feature_importance.head(10)}")
    
    # Save model
    model_path = models_dir / 'random_forest_proper.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump({
            'model': rf_model,
            'scaler': scaler,
            'feature_columns': X_train.columns.tolist(),
            'training_date': datetime.now().isoformat(),
            'dataset': 'BETH SSH Data - Separate Train/Test',
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'test_accuracy': accuracy
        }, f)
    
    logger.info(f"\n✓ Model saved: {model_path}")
    
    logger.info(f"Logistic Regression Accuracy: {lr_accuracy:.4f}")
    logger.info(f"Random Forest Accuracy: {accuracy:.4f}")
    logger.info(f"Decision Tree Accuracy: {dt_accuracy:.4f}")
    logger.info(f"Ensemble Accuracy: {ensemble_accuracy:.4f}")
    
    # Save LR model too
    lr_path = models_dir / 'logistic_regression_proper.pkl'
    with open(lr_path, 'wb') as f:
        pickle.dump({
            'model': lr_model,
            'scaler': scaler,
            'feature_columns': X_train.columns.tolist(),
            'training_date': datetime.now().isoformat(),
            'dataset': 'BETH SSH Data - Separate Train/Test',
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'test_accuracy': lr_accuracy
        }, f)
    
    logger.info(f"✓ Logistic Regression saved: {lr_path}")
    
    # Optionally save Decision Tree and Isolation Forest for further analysis
    # Not required by simulation, so keeping artifacts in memory only
    
    logger.info("\n" + "="*80)
    logger.info("PROPER TRAINING COMPLETED")
    logger.info("="*80)
    logger.info("Now using truly independent test data!")
    logger.info(f"Training samples: {len(X_train):,}")
    logger.info(f"Testing samples: {len(X_test):,}")
    logger.info(f"Final RF Accuracy: {accuracy:.4f}")
    logger.info(f"Final LR Accuracy: {lr_accuracy:.4f}")
    logger.info(f"Final DT Accuracy: {dt_accuracy:.4f}")
    logger.info(f"Final Ensemble Accuracy: {ensemble_accuracy:.4f}")

if __name__ == "__main__":
    train_single_model()