#!/usr/bin/env python3
"""
Data downloader for SSH bruteforce detection project
Downloads and prepares the BETH dataset from Kaggle
"""

import os
import sys
import pandas as pd
import zipfile
from pathlib import Path
import logging

# Make kaggle import optional
try:
    import kaggle
    KAGGLE_AVAILABLE = True
except ImportError:
    KAGGLE_AVAILABLE = False
    kaggle = None

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DatasetDownloader:
    """
    Download and prepare datasets for SSH bruteforce detection
    """
    
    def __init__(self, data_dir='data/'):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Dataset information
        self.datasets = {
            'beth': {
                'kaggle_name': 'katehighnam/beth-dataset',
                'description': 'BETH Dataset - Over 8M events from honeypots',
                'url': 'https://www.kaggle.com/datasets/katehighnam/beth-dataset'
            },
            'siem': {
                'kaggle_name': 'ibtasamahmad/security-information-and-event-management',
                'description': 'SIEM Dataset - Security events',
                'url': 'https://www.kaggle.com/datasets/ibtasamahmad/security-information-and-event-management'
            }
        }
    
    def setup_kaggle_api(self):
        """
        Setup Kaggle API credentials
        """
        if not KAGGLE_AVAILABLE:
            logger.error("Kaggle package not installed. Install with: pip install kaggle")
            return False
            
        try:
            # Check if kaggle.json exists
            kaggle_config = Path.home() / '.kaggle' / 'kaggle.json'
            if not kaggle_config.exists():
                logger.error("Kaggle API credentials not found!")
                logger.info("Please follow these steps:")
                logger.info("1. Go to https://www.kaggle.com/account")
                logger.info("2. Click 'Create New API Token'")
                logger.info("3. Place the downloaded kaggle.json in ~/.kaggle/")
                logger.info("4. Run: chmod 600 ~/.kaggle/kaggle.json")
                return False
            
            # Test API connection
            kaggle.api.authenticate()
            logger.info("Kaggle API authenticated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Kaggle API setup failed: {e}")
            return False
    
    def download_dataset(self, dataset_name='beth', force_download=False):
        """
        Download specified dataset from Kaggle
        """
        if dataset_name not in self.datasets:
            logger.error(f"Unknown dataset: {dataset_name}")
            return False
        
        if not KAGGLE_AVAILABLE:
            logger.error("Kaggle package not available. Using sample data instead.")
            return False
        
        dataset_info = self.datasets[dataset_name]
        dataset_path = self.data_dir / dataset_name
        
        # Check if dataset already exists
        if dataset_path.exists() and not force_download:
            logger.info(f"Dataset {dataset_name} already exists. Use force_download=True to re-download.")
            return True
        
        try:
            logger.info(f"Downloading {dataset_info['description']}...")
            logger.info(f"Source: {dataset_info['url']}")
            
            # Download dataset
            kaggle.api.dataset_download_files(
                dataset_info['kaggle_name'], 
                path=str(dataset_path), 
                unzip=True
            )
            
            logger.info(f"Dataset downloaded to: {dataset_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download dataset {dataset_name}: {e}")
            return False
    
    def list_dataset_files(self, dataset_name='beth'):
        """
        List files in the downloaded dataset
        """
        dataset_path = self.data_dir / dataset_name
        
        if not dataset_path.exists():
            logger.error(f"Dataset {dataset_name} not found. Please download it first.")
            return []
        
        files = list(dataset_path.rglob('*'))
        logger.info(f"Files in {dataset_name} dataset:")
        for file in files:
            if file.is_file():
                logger.info(f"  {file.relative_to(dataset_path)} ({file.stat().st_size / 1024 / 1024:.2f} MB)")
        
        return files
    
    def prepare_ssh_data(self, dataset_name='beth'):
        """
        Prepare SSH-specific data from the downloaded dataset
        """
        dataset_path = self.data_dir / dataset_name
        
        if not dataset_path.exists():
            logger.error(f"Dataset {dataset_name} not found. Please download it first.")
            return None
        
        try:
            # Find CSV files
            csv_files = list(dataset_path.glob('*.csv'))
            
            if not csv_files:
                logger.error("No CSV files found in the dataset")
                return None
            
            logger.info(f"Found {len(csv_files)} CSV files")
            
            # Load and filter SSH-related data
            ssh_data = []
            
            for csv_file in csv_files:
                logger.info(f"Processing {csv_file.name}...")
                
                try:
                    df = pd.read_csv(csv_file)
                    logger.info(f"Loaded {len(df)} rows from {csv_file.name}")
                    
                    # Filter SSH-related entries (port 22 or SSH mentions)
                    ssh_df = df[
                        (df.columns.str.contains('port', case=False).any() and df.filter(regex='port', axis=1).eq(22).any(axis=1)) |
                        df.astype(str).apply(lambda x: x.str.contains('ssh|SSH', case=False, na=False)).any(axis=1)
                    ]
                    
                    if len(ssh_df) > 0:
                        ssh_data.append(ssh_df)
                        logger.info(f"Found {len(ssh_df)} SSH-related entries")
                
                except Exception as e:
                    logger.warning(f"Error processing {csv_file.name}: {e}")
                    continue
            
            if ssh_data:
                # Combine all SSH data
                combined_ssh_data = pd.concat(ssh_data, ignore_index=True)
                
                # Save processed SSH data
                output_path = self.data_dir / f'{dataset_name}_ssh_data.csv'
                combined_ssh_data.to_csv(output_path, index=False)
                
                logger.info(f"SSH data saved to: {output_path}")
                logger.info(f"Total SSH entries: {len(combined_ssh_data)}")
                
                return combined_ssh_data
            
            else:
                logger.warning("No SSH-related data found in the dataset")
                return None
                
        except Exception as e:
            logger.error(f"Error preparing SSH data: {e}")
            return None
    
    def create_sample_dataset(self, output_path=None):
        """
        Create a sample SSH log dataset for testing
        """
        if output_path is None:
            output_path = self.data_dir / 'sample_ssh_logs.csv'
        
        logger.info("Creating sample SSH dataset...")
        
        # Generate sample SSH log data
        import random
        from datetime import datetime, timedelta
        
        sample_data = []
        base_time = datetime.now() - timedelta(days=1)
        
        # Normal SSH activities
        normal_ips = ['192.168.1.10', '192.168.1.20', '192.168.1.30']
        normal_users = ['alice', 'bob', 'charlie', 'admin']
        
        for i in range(1000):
            timestamp = base_time + timedelta(minutes=random.randint(0, 1440))
            sample_data.append({
                'timestamp': timestamp,
                'source_ip': random.choice(normal_ips),
                'username': random.choice(normal_users),
                'event_type': random.choice(['successful_login', 'failed_login']),
                'port': 22,
                'protocol': 'SSH',
                'session_id': f"session_{i}",
                'bytes_transferred': random.randint(100, 5000)
            })
        
        # SSH Bruteforce attacks
        attack_ips = ['203.0.113.50', '198.51.100.25', '10.0.0.100']
        attack_users = ['admin', 'root', 'user', 'test', 'guest']
        
        for attack_ip in attack_ips:
            attack_time = base_time + timedelta(hours=random.randint(1, 23))
            
            # Generate multiple rapid attempts
            for attempt in range(20):
                timestamp = attack_time + timedelta(seconds=attempt * 30)
                sample_data.append({
                    'timestamp': timestamp,
                    'source_ip': attack_ip,
                    'username': random.choice(attack_users),
                    'event_type': 'failed_login',
                    'port': 22,
                    'protocol': 'SSH',
                    'session_id': f"attack_{attack_ip}_{attempt}",
                    'bytes_transferred': 0
                })
        
        # Create DataFrame and save
        df = pd.DataFrame(sample_data)
        df = df.sort_values('timestamp').reset_index(drop=True)
        df.to_csv(output_path, index=False)
        
        logger.info(f"Sample dataset created: {output_path}")
        logger.info(f"Total entries: {len(df)}")
        logger.info(f"SSH attacks: {len(df[df['event_type'] == 'failed_login'])}")
        
        return df

def main():
    """
    Main function to download and prepare datasets
    """
    downloader = DatasetDownloader()
    
    # Setup Kaggle API
    if not downloader.setup_kaggle_api():
        logger.info("Creating sample dataset instead...")
        downloader.create_sample_dataset()
        return
    
    # Download BETH dataset
    if downloader.download_dataset('beth'):
        downloader.list_dataset_files('beth')
        downloader.prepare_ssh_data('beth')
    else:
        logger.info("Failed to download BETH dataset. Creating sample dataset...")
        downloader.create_sample_dataset()

if __name__ == "__main__":
    main()
