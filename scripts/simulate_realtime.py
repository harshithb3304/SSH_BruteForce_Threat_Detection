#!/usr/bin/env python3
"""
Real-time SSH Bruteforce Detection Simulation
Demonstrates live monitoring capabilities using trained models
"""

import pandas as pd
import pickle
import numpy as np
import time
import random
from datetime import datetime, timedelta
import sys
import os

# Add project directory to path
sys.path.append('/home/harshith/Projects/CNS_Lab/SSH_BruteForce_Threat_Detection')

class RealTimeSSHDetector:
    def __init__(self, models_dir):
        self.models_dir = models_dir
        self.load_models()
        self.load_test_data()
        
    def load_models(self):
        """Load trained models and scaler"""
        print("🤖 Loading trained models...")
        
        # Load Random Forest model (saved as dictionary)
        with open(f"{self.models_dir}/random_forest_proper.pkl", 'rb') as f:
            rf_dict = pickle.load(f)
            self.rf_model = rf_dict['model']
            self.scaler = rf_dict['scaler']
            self.feature_columns = rf_dict['feature_columns']
            
        # Check if Logistic Regression exists, if not use RF for both
        lr_path = f"{self.models_dir}/logistic_regression_proper.pkl"
        if os.path.exists(lr_path):
            with open(lr_path, 'rb') as f:
                lr_dict = pickle.load(f)
                self.lr_model = lr_dict['model']
        else:
            print("⚠️  Logistic Regression not found, using Random Forest for ensemble")
            self.lr_model = self.rf_model
            
        print("✓ Models loaded successfully")
        
    def load_test_data(self):
        """Load test dataset for simulation"""
        print("📊 Loading test dataset...")
        
        test_path = "/home/harshith/Projects/CNS_Lab/SSH_BruteForce_Threat_Detection/datasets/labelled_testing_data.csv"
        self.test_data = pd.read_csv(test_path)
        
        # Create labels
        self.test_data['is_attack'] = ((self.test_data['sus'] == 1) | (self.test_data['evil'] == 1)).astype(int)
        
        print(f"✓ Loaded {len(self.test_data)} test samples")
        
    def extract_features(self, row):
        """Extract features from a single row"""
        features = {}
        
        # Parse timestamp if it exists
        if 'timestamp' in row and pd.notna(row['timestamp']):
            try:
                ts = pd.to_datetime(row['timestamp'])
                features['hour'] = ts.hour
                features['minute'] = ts.minute
            except:
                features['hour'] = 12  # Default
                features['minute'] = 0
        else:
            features['hour'] = 12
            features['minute'] = 0
            
        # Process features
        features['processId'] = row.get('processId', 0)
        features['parentProcessId'] = row.get('parentProcessId', 0) 
        features['userId'] = row.get('userId', 0)
        features['eventId'] = row.get('eventId', 0)
        features['argsNum'] = row.get('argsNum', 0)
        features['returnValue'] = row.get('returnValue', 0)
        
        # Binary features
        process_name = str(row.get('processName', '')).lower()
        features['processName_sshd'] = 1 if 'sshd' in process_name else 0
        features['processName_systemd'] = 1 if 'systemd' in process_name else 0
        
        # Event type features
        event_name = str(row.get('eventName', '')).lower()
        features['event_close'] = 1 if 'close' in event_name else 0
        features['event_openat'] = 1 if 'openat' in event_name else 0
        features['event_fstat'] = 1 if 'fstat' in event_name else 0
        features['event_security_file_open'] = 1 if 'security_file_open' in event_name else 0
        features['event_socket'] = 1 if 'socket' in event_name else 0
        features['event_connect'] = 1 if 'connect' in event_name else 0
        
        # Frequency features (simplified for demo)
        features['processId_freq'] = 1  # Placeholder
        features['userId_freq'] = 1     # Placeholder
        
        return features
        
    def predict_attack(self, row):
        """Predict if a log entry indicates an attack"""
        features = self.extract_features(row)
        
        # Convert to DataFrame with correct column order
        feature_df = pd.DataFrame([features])
        
        # Reorder columns to match training
        feature_df = feature_df.reindex(columns=self.feature_columns, fill_value=0)
        
        # Scale features
        feature_vector = self.scaler.transform(feature_df)
        
        # Get predictions from both models
        rf_pred = self.rf_model.predict(feature_vector)[0]
        rf_prob = self.rf_model.predict_proba(feature_vector)[0][1]
        
        lr_pred = self.lr_model.predict(feature_vector)[0] 
        lr_prob = self.lr_model.predict_proba(feature_vector)[0][1]
        
        # Ensemble prediction (average probabilities)
        ensemble_prob = (rf_prob + lr_prob) / 2
        ensemble_pred = 1 if ensemble_prob > 0.5 else 0
        
        return {
            'rf_prediction': rf_pred,
            'rf_confidence': rf_prob,
            'lr_prediction': lr_pred, 
            'lr_confidence': lr_prob,
            'ensemble_prediction': ensemble_pred,
            'ensemble_confidence': ensemble_prob
        }
        
    def simulate_realtime_monitoring(self, duration_seconds=60, sample_rate=10):
        """Simulate real-time monitoring"""
        print(f"🚀 Starting real-time simulation for {duration_seconds} seconds")
        print(f"📈 Processing {sample_rate} samples per second")
        print("=" * 70)
        
        start_time = time.time()
        total_processed = 0
        total_attacks_detected = 0
        total_actual_attacks = 0
        
        # Get random samples for simulation
        sample_indices = np.random.choice(len(self.test_data), 
                                        size=min(duration_seconds * sample_rate, len(self.test_data)),
                                        replace=False)
        
        for i, idx in enumerate(sample_indices):
            if time.time() - start_time > duration_seconds:
                break
                
            row = self.test_data.iloc[idx]
            actual_label = row['is_attack']
            
            # Get prediction
            prediction = self.predict_attack(row)
            
            total_processed += 1
            if actual_label == 1:
                total_actual_attacks += 1
                
            if prediction['ensemble_prediction'] == 1:
                total_attacks_detected += 1
                
                # Display attack alert
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                confidence = prediction['ensemble_confidence'] * 100
                
                print(f"🚨 [{timestamp}] ATTACK DETECTED!")
                print(f"   ProcessID: {row.get('processId', 'N/A')}")
                print(f"   UserID: {row.get('userId', 'N/A')}")
                print(f"   Event: {row.get('eventName', 'N/A')}")
                print(f"   Confidence: {confidence:.1f}%")
                print(f"   RF: {prediction['rf_confidence']:.3f} | LR: {prediction['lr_confidence']:.3f}")
                
                if actual_label == 1:
                    print(f"   Status: ✓ TRUE POSITIVE")
                else:
                    print(f"   Status: ✗ FALSE POSITIVE")
                print("-" * 50)
                
            # Show periodic statistics
            if (i + 1) % (sample_rate * 5) == 0:  # Every 5 seconds
                elapsed = time.time() - start_time
                rate = total_processed / elapsed
                print(f"📊 [{elapsed:.1f}s] Processed: {total_processed} | Rate: {rate:.1f}/sec | Attacks: {total_attacks_detected}")
                
            # Simulate processing delay
            time.sleep(1.0 / sample_rate)
            
        # Final statistics
        elapsed = time.time() - start_time
        print("\n" + "=" * 70)
        print("📈 SIMULATION COMPLETE")
        print(f"⏱️  Duration: {elapsed:.1f} seconds")
        print(f"📊 Total Processed: {total_processed}")
        print(f"🎯 Attacks Detected: {total_attacks_detected}")
        print(f"🔍 Actual Attacks: {total_actual_attacks}")
        print(f"⚡ Processing Rate: {total_processed/elapsed:.1f} samples/second")
        
        if total_actual_attacks > 0:
            detection_rate = (total_attacks_detected / total_actual_attacks) * 100
            print(f"✅ Detection Rate: {detection_rate:.1f}%")

def main():
    """Main simulation function"""
    models_dir = "/home/harshith/Projects/CNS_Lab/SSH_BruteForce_Threat_Detection/models"
    
    # Create detector
    detector = RealTimeSSHDetector(models_dir)
    
    # Run simulation
    print("🎯 SSH Bruteforce Detection - Real-Time Simulation")
    print("📡 Simulating live SSH log monitoring...")
    print("")
    
    try:
        detector.simulate_realtime_monitoring(duration_seconds=15, sample_rate=5)
    except KeyboardInterrupt:
        print("\n🛑 Simulation stopped by user")
    except Exception as e:
        print(f"\n❌ Error during simulation: {e}")

if __name__ == "__main__":
    main()
