#!/usr/bin/env python3
"""
Data preprocessing module for SSH log analysis
Handles parsing and feature extraction from various SSH log formats
"""

import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
import ipaddress
from collections import defaultdict
import json

class SSHLogParser:
    """
    Parser for SSH log files and real-time log streams
    """
    
    def __init__(self):
        # Common SSH log patterns
        self.ssh_patterns = {
            'failed_login': r'Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+)',
            'successful_login': r'Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+)',
            'invalid_user': r'Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+)',
            'connection_closed': r'Connection closed by (\d+\.\d+\.\d+\.\d+) port (\d+)',
            'connection_attempt': r'Connection from (\d+\.\d+\.\d+\.\d+) port (\d+)',
        }
        
        # GeoIP mapping (simplified for demo)
        self.geo_mapping = {
            '10.': 'Private',
            '192.168.': 'Private',
            '172.16.': 'Private',
            '203.0.113.': 'Test Network',
            '198.51.100.': 'Test Network'
        }
    
    def parse_ssh_log_line(self, log_line, timestamp=None):
        """
        Parse a single SSH log line and extract features
        """
        if timestamp is None:
            timestamp = datetime.now()
            
        log_entry = {
            'timestamp': timestamp,
            'raw_log': log_line,
            'event_type': 'unknown',
            'username': None,
            'source_ip': None,
            'port': None,
            'is_valid': False
        }
        
        # Try to match against known patterns
        for event_type, pattern in self.ssh_patterns.items():
            match = re.search(pattern, log_line)
            if match:
                log_entry['event_type'] = event_type
                log_entry['is_valid'] = True
                
                if event_type in ['failed_login', 'successful_login', 'invalid_user']:
                    log_entry['username'] = match.group(1)
                    log_entry['source_ip'] = match.group(2)
                    log_entry['port'] = int(match.group(3))
                elif event_type in ['connection_closed', 'connection_attempt']:
                    log_entry['source_ip'] = match.group(1)
                    log_entry['port'] = int(match.group(2))
                
                break
        
        return log_entry
    
    def parse_log_file(self, file_path):
        """
        Parse an entire SSH log file
        """
        logs = []
        
        try:
            with open(file_path, 'r') as file:
                for line_num, line in enumerate(file):
                    line = line.strip()
                    if line:
                        # Extract timestamp from log line (simplified)
                        timestamp = self._extract_timestamp(line)
                        log_entry = self.parse_ssh_log_line(line, timestamp)
                        log_entry['line_number'] = line_num + 1
                        logs.append(log_entry)
        
        except FileNotFoundError:
            print(f"Log file not found: {file_path}")
        except Exception as e:
            print(f"Error parsing log file: {e}")
        
        return pd.DataFrame(logs)
    
    def _extract_timestamp(self, log_line):
        """
        Extract timestamp from log line (simplified implementation)
        """
        # This is a simplified version - in reality, you'd parse actual syslog timestamps
        return datetime.now()

class FeatureExtractor:
    """
    Extract behavioral and statistical features from SSH logs
    """
    
    def __init__(self, time_window_minutes=60):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.ip_stats = defaultdict(lambda: {
            'total_attempts': 0,
            'failed_attempts': 0,
            'successful_attempts': 0,
            'unique_usernames': set(),
            'first_seen': None,
            'last_seen': None,
            'connection_frequency': [],
            'time_pattern': defaultdict(int)
        })
    
    def extract_features(self, df):
        """
        Extract comprehensive features for ML training
        """
        if df.empty:
            return pd.DataFrame()
        
        features_list = []
        
        for idx, row in df.iterrows():
            features = self._extract_single_features(row, df)
            features_list.append(features)
        
        return pd.DataFrame(features_list)
    
    def _extract_single_features(self, row, full_df):
        """
        Extract features for a single log entry
        """
        features = {}
        source_ip = row.get('source_ip')
        timestamp = row.get('timestamp')
        username = row.get('username')
        event_type = row.get('event_type')
        
        # Basic features
        features['hour'] = timestamp.hour if timestamp else 0
        features['day_of_week'] = timestamp.weekday() if timestamp else 0
        features['minute'] = timestamp.minute if timestamp else 0
        features['is_weekend'] = 1 if timestamp and timestamp.weekday() >= 5 else 0
        
        # IP-based features
        if source_ip:
            # Update IP statistics
            self._update_ip_stats(source_ip, row)
            
            # IP reputation features
            features.update(self._get_ip_reputation_features(source_ip))
            
            # Behavioral features
            features.update(self._get_behavioral_features(source_ip, timestamp, full_df))
        
        # Username features
        if username:
            features.update(self._get_username_features(username))
        
        # Event type features
        features['event_type_encoded'] = self._encode_event_type(event_type)
        features['is_failed_login'] = 1 if event_type == 'failed_login' else 0
        features['is_invalid_user'] = 1 if event_type == 'invalid_user' else 0
        
        # Port features
        port = row.get('port', 22)
        features['is_default_ssh_port'] = 1 if port == 22 else 0
        features['port_encoded'] = port
        
        return features
    
    def _update_ip_stats(self, source_ip, row):
        """
        Update statistics for an IP address
        """
        stats = self.ip_stats[source_ip]
        timestamp = row.get('timestamp')
        event_type = row.get('event_type')
        username = row.get('username')
        
        stats['total_attempts'] += 1
        
        if event_type == 'failed_login':
            stats['failed_attempts'] += 1
        elif event_type == 'successful_login':
            stats['successful_attempts'] += 1
        
        if username:
            stats['unique_usernames'].add(username)
        
        if timestamp:
            if stats['first_seen'] is None:
                stats['first_seen'] = timestamp
            stats['last_seen'] = timestamp
            stats['connection_frequency'].append(timestamp)
            stats['time_pattern'][timestamp.hour] += 1
    
    def _get_ip_reputation_features(self, source_ip):
        """
        Extract IP reputation and geographic features
        """
        features = {}
        
        # Geographic classification (simplified)
        is_private = any(source_ip.startswith(prefix) for prefix in ['10.', '192.168.', '172.16.'])
        features['is_private_ip'] = 1 if is_private else 0
        
        # IP classification
        try:
            ip_obj = ipaddress.ip_address(source_ip)
            features['is_loopback'] = 1 if ip_obj.is_loopback else 0
            features['is_multicast'] = 1 if ip_obj.is_multicast else 0
        except:
            features['is_loopback'] = 0
            features['is_multicast'] = 0
        
        return features
    
    def _get_behavioral_features(self, source_ip, current_time, full_df):
        """
        Extract behavioral features based on historical data
        """
        features = {}
        stats = self.ip_stats[source_ip]
        
        # Frequency-based features
        features['total_attempts'] = stats['total_attempts']
        features['failed_attempts'] = stats['failed_attempts']
        features['successful_attempts'] = stats['successful_attempts']
        features['failure_rate'] = (stats['failed_attempts'] / max(stats['total_attempts'], 1))
        
        # Username diversity
        features['unique_usernames_count'] = len(stats['unique_usernames'])
        features['username_diversity'] = len(stats['unique_usernames']) / max(stats['total_attempts'], 1)
        
        # Time-based features
        if stats['first_seen'] and stats['last_seen']:
            duration = (stats['last_seen'] - stats['first_seen']).total_seconds()
            features['session_duration'] = duration
            features['attempts_per_minute'] = stats['total_attempts'] / max(duration / 60, 1)
        else:
            features['session_duration'] = 0
            features['attempts_per_minute'] = 0
        
        # Connection pattern features
        if len(stats['connection_frequency']) > 1:
            intervals = []
            for i in range(1, len(stats['connection_frequency'])):
                interval = (stats['connection_frequency'][i] - stats['connection_frequency'][i-1]).total_seconds()
                intervals.append(interval)
            
            features['avg_connection_interval'] = np.mean(intervals) if intervals else 0
            features['connection_interval_variance'] = np.var(intervals) if intervals else 0
        else:
            features['avg_connection_interval'] = 0
            features['connection_interval_variance'] = 0
        
        # Time pattern analysis
        hour_distribution = list(stats['time_pattern'].values())
        features['time_pattern_entropy'] = self._calculate_entropy(hour_distribution)
        
        return features
    
    def _get_username_features(self, username):
        """
        Extract username-based features
        """
        features = {}
        
        # Common administrative usernames
        admin_usernames = ['admin', 'administrator', 'root', 'sa', 'admin1', 'admin2']
        features['is_admin_username'] = 1 if username.lower() in admin_usernames else 0
        
        # Common test/default usernames
        test_usernames = ['test', 'guest', 'user', 'demo', 'temp', 'test1', 'user1']
        features['is_test_username'] = 1 if username.lower() in test_usernames else 0
        
        # Username characteristics
        features['username_length'] = len(username)
        features['username_has_digits'] = 1 if any(c.isdigit() for c in username) else 0
        features['username_has_special'] = 1 if any(not c.isalnum() for c in username) else 0
        
        return features
    
    def _encode_event_type(self, event_type):
        """
        Encode event types numerically
        """
        encoding = {
            'successful_login': 1,
            'failed_login': 2,
            'invalid_user': 3,
            'connection_closed': 4,
            'connection_attempt': 5,
            'unknown': 0
        }
        return encoding.get(event_type, 0)
    
    def _calculate_entropy(self, distribution):
        """
        Calculate entropy of a distribution
        """
        if not distribution or sum(distribution) == 0:
            return 0
        
        total = sum(distribution)
        probabilities = [count / total for count in distribution if count > 0]
        
        entropy = -sum(p * np.log2(p) for p in probabilities)
        return entropy

def preprocess_beth_dataset(file_path):
    """
    Preprocess the BETH dataset for SSH bruteforce detection
    """
    print("Loading BETH dataset...")
    
    try:
        # Load the dataset (assuming CSV format)
        df = pd.read_csv(file_path)
        
        # Initialize feature extractor
        extractor = FeatureExtractor()
        
        # Extract features
        print("Extracting features...")
        features_df = extractor.extract_features(df)
        
        # Create labels based on attack patterns
        print("Creating labels...")
        labels = create_bruteforce_labels(df, features_df)
        
        return features_df, labels, df
        
    except Exception as e:
        print(f"Error preprocessing dataset: {e}")
        return None, None, None

def create_bruteforce_labels(original_df, features_df):
    """
    Create labels for SSH bruteforce attack detection
    """
    labels = []
    
    for idx, (_, feature_row) in enumerate(features_df.iterrows()):
        is_bruteforce = 0
        
        # Label as bruteforce based on multiple criteria
        if (feature_row.get('failed_attempts', 0) >= 5 and 
            feature_row.get('failure_rate', 0) > 0.8):
            is_bruteforce = 1
        
        if (feature_row.get('attempts_per_minute', 0) > 2 and 
            feature_row.get('unique_usernames_count', 0) > 3):
            is_bruteforce = 1
        
        if (feature_row.get('is_admin_username', 0) == 1 and 
            feature_row.get('failed_attempts', 0) >= 3):
            is_bruteforce = 1
        
        labels.append(is_bruteforce)
    
    return np.array(labels)

if __name__ == "__main__":
    # Example usage
    parser = SSHLogParser()
    extractor = FeatureExtractor()
    
    # Parse sample log lines
    sample_logs = [
        "Failed password for admin from 203.0.113.50 port 22",
        "Accepted password for alice from 192.168.1.10 port 22",
        "Invalid user test from 10.0.0.100 port 22",
        "Failed password for root from 203.0.113.50 port 22"
    ]
    
    parsed_logs = []
    for log in sample_logs:
        parsed = parser.parse_ssh_log_line(log)
        parsed_logs.append(parsed)
    
    df = pd.DataFrame(parsed_logs)
    features = extractor.extract_features(df)
    
    print("Sample Features:")
    print(features.head())
