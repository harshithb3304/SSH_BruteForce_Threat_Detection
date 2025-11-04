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
        """Load ensemble model (supervised + unsupervised)"""
        print("🤖 Loading ensemble model...")
        
        # Load ensemble model (saved as dictionary)
        ensemble_path = f"{self.models_dir}/ensemble.pkl"
        if not os.path.exists(ensemble_path):
            raise FileNotFoundError(f"Ensemble model not found: {ensemble_path}\nPlease run: python scripts/proper_training.py")
        
        with open(ensemble_path, 'rb') as f:
            ensemble_dict = pickle.load(f)
            self.lr_model = ensemble_dict['supervised_model']  # Logistic Regression
            self.if_model = ensemble_dict['unsupervised_model']  # Isolation Forest
            self.scaler = ensemble_dict['scaler']
            self.feature_columns = ensemble_dict['feature_columns']
            
        print("✓ Ensemble model loaded (LR + Isolation Forest)")
        
    def load_test_data(self):
        """Load test dataset for simulation"""
        print("📊 Loading test dataset...")
        
        test_path = "/home/harshith/Projects/CNS_Lab/SSH_BruteForce_Threat_Detection/datasets/labelled_testing_data.csv"
        self.test_data = pd.read_csv(test_path)
        
        # Create labels
        self.test_data['is_attack'] = ((self.test_data['sus'] == 1) | (self.test_data['evil'] == 1)).astype(int)
        
        print(f"✓ Loaded {len(self.test_data)} test samples")
        
    def extract_features(self, row):
        """Extract features from a single row (matches training feature extraction)"""
        features = {}
        
        # Process features (numerical)
        features['processId'] = row.get('processId', 0)
        features['parentProcessId'] = row.get('parentProcessId', 0) 
        features['userId'] = row.get('userId', 0)
        features['eventId'] = row.get('eventId', 0)
        features['argsNum'] = row.get('argsNum', 0)
        features['returnValue'] = row.get('returnValue', 0)
        
        # Process type features (binary)
        process_name = str(row.get('processName', '')).lower()
        features['is_sshd'] = 1 if process_name == 'sshd' else 0
        features['is_systemd'] = 1 if process_name == 'systemd' else 0
        
        # Event type features (binary, match training)
        event_name = str(row.get('eventName', '')).lower()
        features['event_close'] = 1 if event_name == 'close' else 0
        features['event_openat'] = 1 if event_name == 'openat' else 0
        features['event_socket'] = 1 if event_name == 'socket' else 0
        
        # Time feature (match training: hour from timestamp % 86400 / 3600)
        if 'timestamp' in row and pd.notna(row['timestamp']):
            try:
                timestamp_val = float(row['timestamp'])
                features['hour'] = int((timestamp_val % 86400) / 3600)
            except:
                features['hour'] = 12  # Default
        else:
            features['hour'] = 12
        
        # Root user check
        features['is_root_user'] = 1 if row.get('userId', 0) == 0 else 0
        
        return features
        
    def predict_attack(self, row):
        """Predict if a log entry indicates an attack using ensemble (supervised + unsupervised)"""
        features = self.extract_features(row)
        
        # Convert to DataFrame with correct column order
        feature_df = pd.DataFrame([features])
        
        # Reorder columns to match training
        feature_df = feature_df.reindex(columns=self.feature_columns, fill_value=0)
        
        # Scale features
        feature_vector = self.scaler.transform(feature_df)
        
        # Supervised prediction (Logistic Regression)
        lr_pred = self.lr_model.predict(feature_vector)[0]
        lr_prob = self.lr_model.predict_proba(feature_vector)[0][1]
        
        # Unsupervised prediction (Isolation Forest: -1=anomaly, 1=normal)
        if_pred_raw = self.if_model.predict(feature_vector)[0]
        if_pred = 1 if if_pred_raw == -1 else 0  # Convert: -1→attack(1), 1→normal(0)
        if_score = self.if_model.score_samples(feature_vector)[0]  # Lower = more anomalous
        if_prob = 1 / (1 + np.exp(-if_score))  # Normalize to [0,1]
        
        # Ensemble: Both models vote
        # If both agree → use that prediction
        # If they disagree → trust supervised (more reliable for known patterns)
        ensemble_pred = lr_pred if lr_pred == if_pred else lr_pred
        # Note: When both agree, we're more confident. When they disagree, trust LR.
        ensemble_prob = (lr_prob + if_prob) / 2.0
        
        return {
            'lr_prediction': lr_pred,
            'lr_confidence': lr_prob,
            'if_prediction': if_pred,
            'if_confidence': if_prob,
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
                print(f"   LR (Supervised): {prediction['lr_confidence']:.3f} | IF (Unsupervised): {prediction['if_confidence']:.3f}")
                
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
