#!/usr/bin/env python3
"""
Test script for SSH Detector using trained BETH model
"""

import sys
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_trained_model():
    """Load the trained Random Forest model"""
    model_path = Path('models/random_forest_beth.pkl')
    
    if not model_path.exists():
        logger.error(f"Model file not found: {model_path}")
        return None
    
    with open(model_path, 'rb') as f:
        model_data = pickle.load(f)
    
    logger.info(f"✓ Model loaded from {model_path}")
    logger.info(f"  Training date: {model_data['training_date']}")
    logger.info(f"  Dataset: {model_data['dataset']}")
    logger.info(f"  Training samples: {model_data['samples']:,}")
    
    return model_data

def extract_features_from_log(log_entry):
    """Extract features from a single log entry (matching training features)"""
    # This would extract the same 19 features used during training
    features = {
        'timestamp': log_entry.get('timestamp', 0),
        'processId': log_entry.get('processId', 0),
        'parentProcessId': log_entry.get('parentProcessId', 0),
        'userId': log_entry.get('userId', 0),
        'eventId': log_entry.get('eventId', 0),
        'argsNum': log_entry.get('argsNum', 0),
        'returnValue': log_entry.get('returnValue', 0),
        'processName_sshd': 1 if log_entry.get('processName') == 'sshd' else 0,
        'processName_systemd': 1 if log_entry.get('processName') == 'systemd' else 0,
        'event_close': 1 if log_entry.get('eventName') == 'close' else 0,
        'event_openat': 1 if log_entry.get('eventName') == 'openat' else 0,
        'event_fstat': 1 if log_entry.get('eventName') == 'fstat' else 0,
        'event_security_file_open': 1 if log_entry.get('eventName') == 'security_file_open' else 0,
        'event_socket': 1 if log_entry.get('eventName') == 'socket' else 0,
        'event_connect': 1 if log_entry.get('eventName') == 'connect' else 0,
        'hour': int(log_entry.get('timestamp', 0) % 86400 / 3600),
        'minute': int(log_entry.get('timestamp', 0) % 3600 / 60),
        'processId_freq': log_entry.get('processId_freq', 0),
        'userId_freq': log_entry.get('userId_freq', 0),
    }
    
    return pd.DataFrame([features])

def predict_attack(model_data, log_entry):
    """Predict if a log entry is an attack"""
    model = model_data['model']
    scaler = model_data['scaler']
    
    # Extract features
    features_df = extract_features_from_log(log_entry)
    
    # Scale features
    features_scaled = scaler.transform(features_df)
    
    # Predict
    prediction = model.predict(features_scaled)[0]
    probability = model.predict_proba(features_scaled)[0]
    
    return {
        'is_attack': bool(prediction),
        'probability_normal': float(probability[0]),
        'probability_attack': float(probability[1]),
        'confidence': float(max(probability))
    }

def test_detector():
    """Test the detector with sample log entries"""
    logger.info("="*80)
    logger.info("SSH BRUTEFORCE DETECTOR TEST")
    logger.info("="*80)
    
    # Load model
    model_data = load_trained_model()
    if model_data is None:
        return
    
    # Test with sample log entries
    logger.info("\n=== Testing with Sample Log Entries ===")
    
    # Normal SSH activity
    normal_log = {
        'timestamp': 1000.0,
        'processId': 1047,
        'parentProcessId': 940,
        'userId': 1000,
        'eventId': 3,
        'eventName': 'close',
        'argsNum': 1,
        'returnValue': 0,
        'processName': 'sshd',
        'processId_freq': 5,
        'userId_freq': 10
    }
    
    logger.info("\n📋 Test 1: Normal SSH Activity")
    logger.info(f"   Process: {normal_log['processName']}, Event: {normal_log['eventName']}")
    result = predict_attack(model_data, normal_log)
    logger.info(f"   Result: {'🔴 ATTACK' if result['is_attack'] else '🟢 NORMAL'}")
    logger.info(f"   Attack Probability: {result['probability_attack']:.4f}")
    logger.info(f"   Confidence: {result['confidence']:.4f}")
    
    # Suspicious activity
    suspicious_log = {
        'timestamp': 2000.0,
        'processId': 2500,
        'parentProcessId': 940,
        'userId': 0,
        'eventId': 257,
        'eventName': 'socket',
        'argsNum': 3,
        'returnValue': 0,
        'processName': 'sshd',
        'processId_freq': 50,
        'userId_freq': 100
    }
    
    logger.info("\n📋 Test 2: Suspicious Activity (High Frequency)")
    logger.info(f"   Process: {suspicious_log['processName']}, Event: {suspicious_log['eventName']}")
    logger.info(f"   User: {suspicious_log['userId']}, Frequency: {suspicious_log['userId_freq']}")
    result = predict_attack(model_data, suspicious_log)
    logger.info(f"   Result: {'🔴 ATTACK' if result['is_attack'] else '🟢 NORMAL'}")
    logger.info(f"   Attack Probability: {result['probability_attack']:.4f}")
    logger.info(f"   Confidence: {result['confidence']:.4f}")
    
    # Load and test on real BETH data samples
    logger.info("\n=== Testing on Real BETH Data Samples ===")
    
    try:
        df = pd.read_csv('data/beth_ssh_data.csv', nrows=10, low_memory=False)
        
        for idx, row in df.iterrows():
            log_entry = row.to_dict()
            result = predict_attack(model_data, log_entry)
            
            actual_label = "ATTACK" if (row['sus'] == 1 or row['evil'] == 1) else "NORMAL"
            predicted_label = "ATTACK" if result['is_attack'] else "NORMAL"
            match = "✓" if actual_label == predicted_label else "✗"
            
            logger.info(f"\n   Sample {idx+1}: {match}")
            logger.info(f"   Actual: {actual_label}, Predicted: {predicted_label}")
            logger.info(f"   Attack Probability: {result['probability_attack']:.4f}")
            
    except Exception as e:
        logger.error(f"Could not test on real data: {e}")
    
    logger.info("\n" + "="*80)
    logger.info("DETECTOR TEST COMPLETED")
    logger.info("="*80)

if __name__ == "__main__":
    test_detector()
