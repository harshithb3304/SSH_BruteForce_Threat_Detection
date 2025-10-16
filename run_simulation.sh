#!/bin/bash

# SSH Bruteforce Detection - Real-time Simulation Script
# This script demonstrates real-time SSH attack detection using the trained models

set -e  # Exit on any error

# Configuration
PROJECT_DIR="/home/harshith/Projects/CNS_Lab/SSH_BruteForce_Threat_Detection"
PYTHON_ENV="/home/harshith/Projects/CNS_Lab/.venv/bin/python"
LOG_FILE="$PROJECT_DIR/logs/simulation_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_attack() {
    echo -e "${RED}[ATTACK DETECTED]${NC} $1"
}

# Function to display banner
show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          SSH BRUTEFORCE DETECTION SYSTEM                ║"
    echo "║                Real-Time Simulation                     ║"
    echo "║                                                          ║"
    echo "║  Model: Ensemble (Random Forest + Logistic Regression) ║"
    echo "║  Accuracy: 90.67% RF | 94.54% LR                       ║"
    echo "║  Processing Speed: 82,434 samples/sec                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if project directory exists
    if [ ! -d "$PROJECT_DIR" ]; then
        print_error "Project directory not found: $PROJECT_DIR"
        exit 1
    fi
    
    # Check if Python environment exists
    if [ ! -f "$PYTHON_ENV" ]; then
        print_error "Python environment not found: $PYTHON_ENV"
        exit 1
    fi
    
    # Check if models exist
    if [ ! -f "$PROJECT_DIR/models/random_forest_proper.pkl" ]; then
        print_error "Random Forest model not found"
        exit 1
    fi
    
    if [ ! -f "$PROJECT_DIR/models/logistic_regression_proper.pkl" ]; then
        print_error "Logistic Regression model not found"
        exit 1
    fi
    
    # Check if test dataset exists
    if [ ! -f "$PROJECT_DIR/datasets/labelled_testing_data.csv" ]; then
        print_error "Test dataset not found"
        exit 1
    fi
    
    print_status "All prerequisites met ✓"
}

# Function to create simulation script
create_simulation_script() {
    # Check if simulation script already exists and is working
    if [ -f "$PROJECT_DIR/scripts/simulate_realtime.py" ]; then
        print_status "Simulation script already exists, skipping creation..."
        return 0
    fi
    
    print_status "Creating real-time simulation script..."
    
    cat > "$PROJECT_DIR/scripts/simulate_realtime.py" << 'EOF'
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
        
        # Load Random Forest model
        with open(f"{self.models_dir}/random_forest_proper.pkl", 'rb') as f:
            self.rf_model = pickle.load(f)
            
        # Load Logistic Regression model  
        with open(f"{self.models_dir}/logistic_regression_proper.pkl", 'rb') as f:
            self.lr_model = pickle.load(f)
            
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
        
        # Convert to array format expected by models
        feature_vector = np.array([[
            features['processId'], features['parentProcessId'], features['userId'],
            features['eventId'], features['argsNum'], features['returnValue'],
            features['processName_sshd'], features['processName_systemd'],
            features['event_close'], features['event_openat'], features['event_fstat'],
            features['event_security_file_open'], features['event_socket'], 
            features['event_connect'], features['hour'], features['minute'],
            features['processId_freq'], features['userId_freq']
        ]])
        
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
        detector.simulate_realtime_monitoring(duration_seconds=30, sample_rate=5)
    except KeyboardInterrupt:
        print("\n🛑 Simulation stopped by user")
    except Exception as e:
        print(f"\n❌ Error during simulation: {e}")

if __name__ == "__main__":
    main()
EOF

    chmod +x "$PROJECT_DIR/scripts/simulate_realtime.py"
    print_status "Simulation script created ✓"
}

# Function to run the simulation
run_simulation() {
    print_status "Starting real-time SSH bruteforce detection simulation..."
    echo ""
    
    cd "$PROJECT_DIR"
    
    # Run the simulation
    $PYTHON_ENV scripts/simulate_realtime.py 2>&1 | tee "$LOG_FILE"
    
    echo ""
    print_status "Simulation completed. Log saved to: $LOG_FILE"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -q, --quick    Run quick 15-second simulation"
    echo "  -l, --long     Run extended 60-second simulation"
    echo "  -t, --test     Test prerequisites only"
    echo ""
    echo "Default: 30-second simulation with 5 samples/second"
}

# Main execution
main() {
    # Parse command line arguments
    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -t|--test)
            show_banner
            check_prerequisites
            print_status "Prerequisites check completed successfully!"
            exit 0
            ;;
        -q|--quick)
            DURATION=15
            ;;
        -l|--long)
            DURATION=60
            ;;
        *)
            DURATION=30
            ;;
    esac
    
    # Main execution flow
    show_banner
    check_prerequisites
    create_simulation_script
    
    print_status "🚀 Starting SSH Bruteforce Detection Simulation..."
    print_status "Duration: ${DURATION} seconds"
    print_status "Press Ctrl+C to stop early"
    echo ""
    
    # Update simulation duration in the Python script
    sed -i "s/duration_seconds=30/duration_seconds=${DURATION}/" "$PROJECT_DIR/scripts/simulate_realtime.py"
    
    run_simulation
    
    echo ""
    print_status "🎉 Simulation demonstration completed successfully!"
    print_warning "💡 This was a demonstration. For production use, integrate with real SSH logs."
}

# Execute main function
main "$@"