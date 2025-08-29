#!/usr/bin/env python3
"""
Test SSH detection model on real external datasets
Uses KDD Cup 99 and simulated real-world SSH logs
"""

import pandas as pd
import numpy as np
import requests
import io
from urllib.parse import urlparse
from improved_detector import ImprovedSSHDetector
from validate_overfitting import ExternalDatasetValidator
import matplotlib.pyplot as plt

def download_kdd_sample():
    """
    Download a sample of KDD Cup 99 data
    """
    print("Downloading KDD Cup 99 sample data...")
    
    # KDD Cup 99 10% sample URL
    url = "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz"
    
    try:
        # Column names for KDD dataset
        kdd_columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'attack_type'
        ]
        
        # Download the data
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            # Read compressed data
            df = pd.read_csv(io.BytesIO(response.content), compression='gzip', 
                           names=kdd_columns, header=None)
            
            print(f"Downloaded KDD dataset: {len(df)} records")
            return df
        else:
            print(f"Failed to download KDD data: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"Error downloading KDD data: {e}")
        return None

def convert_kdd_to_ssh_format(kdd_df):
    """
    Convert KDD Cup data to SSH log format
    """
    print("Converting KDD data to SSH log format...")
    
    # Filter for relevant attack types and normal traffic
    ssh_related = kdd_df[
        (kdd_df['service'] == 'ssh') |
        (kdd_df['attack_type'].str.contains('guess|brute|password', case=False, na=False)) |
        (kdd_df['num_failed_logins'] > 0) |
        (kdd_df['attack_type'] == 'normal.')
    ].copy()
    
    if len(ssh_related) == 0:
        print("No SSH-related data found in KDD dataset")
        return None
    
    print(f"Found {len(ssh_related)} SSH-related records")
    
    # Convert to SSH log format
    ssh_logs = []
    base_time = pd.Timestamp.now() - pd.Timedelta(days=1)
    
    for idx, row in ssh_related.iterrows():
        # Generate synthetic IP addresses based on KDD features
        if row['dst_host_count'] > 50:  # Suspicious activity
            source_ip = f"203.0.113.{np.random.randint(1, 255)}"
        elif row['same_srv_rate'] < 0.1:  # Scanning behavior
            source_ip = f"198.51.100.{np.random.randint(1, 255)}"
        else:  # Normal traffic
            source_ip = f"192.168.1.{np.random.randint(1, 255)}"
        
        # Generate username based on attack patterns
        if row['num_failed_logins'] > 3 or 'guess' in str(row['attack_type']):
            username = np.random.choice(['admin', 'root', 'user', 'test'])
        else:
            username = np.random.choice(['alice', 'bob', 'charlie', 'service'])
        
        # Determine event type
        if row['logged_in'] == 1:
            event_type = 'successful_login'
        elif row['num_failed_logins'] > 0:
            event_type = 'failed_login'
        else:
            event_type = np.random.choice(['successful_login', 'failed_login'], p=[0.8, 0.2])
        
        # Generate timestamp
        timestamp = base_time + pd.Timedelta(minutes=np.random.randint(0, 1440))
        
        ssh_logs.append({
            'timestamp': timestamp,
            'source_ip': source_ip,
            'username': username,
            'event_type': event_type,
            'port': 22,
            'kdd_attack_type': row['attack_type'],
            'kdd_failed_logins': row['num_failed_logins'],
            'kdd_logged_in': row['logged_in']
        })
    
    ssh_df = pd.DataFrame(ssh_logs)
    print(f"Converted to {len(ssh_df)} SSH log entries")
    
    return ssh_df

def create_university_dataset():
    """
    Create a realistic university network SSH dataset
    """
    print("Creating university network SSH dataset...")
    
    import random
    from datetime import datetime, timedelta
    
    data = []
    base_time = datetime.now() - timedelta(days=30)
    
    # University-specific characteristics
    lab_ips = [f"10.{random.randint(1,50)}.{random.randint(1,255)}.{random.randint(1,50)}" for _ in range(100)]
    dorm_ips = [f"172.16.{random.randint(1,100)}.{random.randint(1,255)}" for _ in range(200)]
    external_ips = [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(50)]
    
    students = [f"student{i}" for i in range(1, 501)]
    faculty = ['prof.smith', 'prof.jones', 'dr.wilson', 'admin.cs', 'lab.manager']
    attackers = ['admin', 'root', 'user', 'test', 'guest']
    
    # Normal university traffic (8000 entries)
    for i in range(8000):
        # Time patterns - more activity during day
        hour = random.choices(range(24), weights=[1,1,1,1,1,2,3,5,8,10,10,10,10,8,8,8,6,5,4,3,2,2,1,1])[0]
        timestamp = base_time + timedelta(days=random.randint(0, 29), hours=hour, minutes=random.randint(0, 59))
        
        # Choose user type and IP
        if random.random() < 0.8:  # 80% students
            username = random.choice(students)
            source_ip = random.choice(lab_ips + dorm_ips)
            success_rate = 0.9
        else:  # 20% faculty/staff
            username = random.choice(faculty)
            source_ip = random.choice(lab_ips)
            success_rate = 0.95
        
        event_type = 'successful_login' if random.random() < success_rate else 'failed_login'
        
        data.append({
            'timestamp': timestamp,
            'source_ip': source_ip,
            'username': username,
            'event_type': event_type,
            'port': 22,
            'network_type': 'university'
        })
    
    # Attack scenarios (2000 entries)
    attack_scenarios = [
        {'type': 'credential_stuffing', 'ips': 10, 'attempts_per_ip': 50},
        {'type': 'targeted_bruteforce', 'ips': 5, 'attempts_per_ip': 100},
        {'type': 'dictionary_attack', 'ips': 15, 'attempts_per_ip': 30}
    ]
    
    for scenario in attack_scenarios:
        attack_ips = random.sample(external_ips, scenario['ips'])
        
        for attack_ip in attack_ips:
            for attempt in range(scenario['attempts_per_ip']):
                # Attacks happen mostly at night
                hour = random.choices(range(24), weights=[3,3,3,3,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,3,3,3,3])[0]
                timestamp = base_time + timedelta(
                    days=random.randint(0, 29),
                    hours=hour,
                    minutes=random.randint(0, 59),
                    seconds=attempt * random.randint(1, 30)
                )
                
                # Choose target username
                if scenario['type'] == 'credential_stuffing':
                    username = random.choice(students + faculty)
                else:
                    username = random.choice(attackers + faculty[:2])
                
                # Most attacks fail
                event_type = 'failed_login' if random.random() < 0.98 else 'successful_login'
                
                data.append({
                    'timestamp': timestamp,
                    'source_ip': attack_ip,
                    'username': username,
                    'event_type': event_type,
                    'port': 22,
                    'network_type': 'university',
                    'attack_scenario': scenario['type']
                })
    
    df = pd.DataFrame(data)
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    print(f"Created university dataset: {len(df)} entries")
    attack_entries = len(df[df.get('attack_scenario').notna()]) if 'attack_scenario' in df.columns else 0
    print(f"Normal entries: {len(df) - attack_entries}")
    print(f"Attack entries: {attack_entries}")
    
    return df

def comprehensive_external_validation():
    """
    Comprehensive validation on multiple external datasets
    """
    print("🔬 COMPREHENSIVE EXTERNAL VALIDATION")
    print("="*60)
    
    # Create improved detector
    detector = ImprovedSSHDetector()
    validator = ExternalDatasetValidator()
    
    # Train on realistic data
    print("\n1. Training on realistic baseline data...")
    training_data = validator.create_realistic_ssh_data(4000)
    X_test, y_test, results = detector.train_with_validation(training_data)
    
    baseline_accuracy = results[detector.best_model_name]['test_accuracy']
    print(f"Baseline test accuracy: {baseline_accuracy:.3f}")
    
    # Test datasets
    test_results = {}
    
    # Test 1: University dataset
    print("\n2. Testing on university network data...")
    university_data = create_university_dataset()
    univ_results = detector.test_on_external_data(university_data)
    test_results['university'] = univ_results['accuracy']
    
    # Test 2: KDD Cup derived data
    print("\n3. Testing on KDD Cup derived data...")
    kdd_data = download_kdd_sample()
    if kdd_data is not None:
        ssh_kdd = convert_kdd_to_ssh_format(kdd_data)
        if ssh_kdd is not None and len(ssh_kdd) > 100:
            kdd_results = detector.test_on_external_data(ssh_kdd)
            test_results['kdd_derived'] = kdd_results['accuracy']
        else:
            print("Insufficient KDD SSH data, skipping...")
            test_results['kdd_derived'] = None
    else:
        print("KDD data unavailable, skipping...")
        test_results['kdd_derived'] = None
    
    # Test 3: Different time periods
    print("\n4. Testing on different time periods...")
    old_data = validator.create_realistic_ssh_data(1500)
    # Shift timestamps to simulate different time period
    old_data['timestamp'] = old_data['timestamp'] - pd.Timedelta(days=60)
    temporal_results = detector.test_on_external_data(old_data)
    test_results['temporal_shift'] = temporal_results['accuracy']
    
    # Summary
    print("\n" + "="*60)
    print("EXTERNAL VALIDATION SUMMARY")
    print("="*60)
    
    print(f"Baseline (training data): {baseline_accuracy:.3f}")
    print("\nExternal dataset performance:")
    
    valid_tests = 0
    total_drop = 0
    
    for dataset, accuracy in test_results.items():
        if accuracy is not None:
            drop = baseline_accuracy - accuracy
            total_drop += drop
            valid_tests += 1
            
            status = "✅" if drop < 0.1 else "⚠️" if drop < 0.2 else "❌"
            print(f"  {dataset:15}: {accuracy:.3f} (drop: {drop:+.3f}) {status}")
        else:
            print(f"  {dataset:15}: UNAVAILABLE")
    
    if valid_tests > 0:
        avg_drop = total_drop / valid_tests
        print(f"\nAverage performance drop: {avg_drop:.3f}")
        
        if avg_drop < 0.1:
            print("🎉 EXCELLENT GENERALIZATION - Model is robust!")
        elif avg_drop < 0.2:
            print("👍 GOOD GENERALIZATION - Acceptable performance")
        else:
            print("⚠️  POOR GENERALIZATION - Needs improvement")
    
    # Plot results
    plot_external_validation(baseline_accuracy, test_results)
    
    return test_results

def plot_external_validation(baseline, test_results):
    """
    Plot external validation results
    """
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    
    # Performance comparison
    datasets = ['Baseline'] + [k for k, v in test_results.items() if v is not None]
    accuracies = [baseline] + [v for v in test_results.values() if v is not None]
    
    colors = ['green'] + ['orange'] * (len(accuracies) - 1)
    bars = axes[0].bar(datasets, accuracies, color=colors, alpha=0.7)
    
    axes[0].set_title('External Validation Results')
    axes[0].set_ylabel('Accuracy')
    axes[0].set_ylim(0, 1)
    axes[0].tick_params(axis='x', rotation=45)
    
    # Add value labels
    for bar, acc in zip(bars, accuracies):
        axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                    f'{acc:.3f}', ha='center', va='bottom', fontweight='bold')
    
    # Performance drop analysis
    drops = [0] + [baseline - v for v in test_results.values() if v is not None]
    external_datasets = datasets[1:]
    external_drops = drops[1:]
    
    colors_drop = ['green' if d < 0.1 else 'orange' if d < 0.2 else 'red' for d in external_drops]
    
    axes[1].bar(external_datasets, external_drops, color=colors_drop, alpha=0.7)
    axes[1].set_title('Performance Drop on External Data')
    axes[1].set_ylabel('Accuracy Drop')
    axes[1].tick_params(axis='x', rotation=45)
    axes[1].axhline(y=0.1, color='orange', linestyle='--', label='Acceptable threshold')
    axes[1].axhline(y=0.2, color='red', linestyle='--', label='Poor threshold')
    axes[1].legend()
    
    plt.tight_layout()
    plt.savefig('external_validation_results.png', dpi=300, bbox_inches='tight')
    plt.show()

if __name__ == "__main__":
    comprehensive_external_validation()
