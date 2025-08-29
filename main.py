#!/usr/bin/env python3
"""
Main execution script for SSH Bruteforce Detection System
Integrates all components: data processing, model training, evaluation, and real-time detection
"""

import os
import sys
import argparse
import logging
from pathlib import Path
import pandas as pd
import numpy as np
from datetime import datetime

# Add src directory to path
sys.path.append(str(Path(__file__).parent / 'src'))

# Import our modules
from ssh_detector import SSHBruteforceDetector, generate_sample_ssh_data
from realtime_monitor import RealTimeSSHMonitor
from src.preprocessing.log_parser import SSHLogParser, FeatureExtractor, preprocess_beth_dataset
from src.data.download_data import DatasetDownloader
from src.models.neural_networks import TensorFlowSSHDetector, train_ensemble_models
from src.evaluation.model_evaluation import evaluate_ssh_detection_system
from src.response.threat_response import ThreatResponseManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ssh_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SSHDetectionSystem:
    """
    Main SSH Bruteforce Detection System orchestrator
    """
    
    def __init__(self, config_file=None):
        self.config = self.load_config(config_file)
        self.data_dir = Path('data')
        self.models_dir = Path('models')
        self.reports_dir = Path('reports')
        
        # Create directories
        for directory in [self.data_dir, self.models_dir, self.reports_dir]:
            directory.mkdir(exist_ok=True)
        
        # Initialize components
        self.detector = None
        self.monitor = None
        self.response_manager = None
        self.models = {}
        
    def load_config(self, config_file):
        """Load system configuration"""
        default_config = {
            'data_source': 'sample',  # 'sample', 'beth', 'file'
            'model_types': ['random_forest', 'neural_network'],
            'evaluation_enabled': True,
            'real_time_monitoring': False,
            'automated_response': False
        }
        
        if config_file and Path(config_file).exists():
            import json
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def setup_data(self):
        """Setup and prepare data for training"""
        logger.info("Setting up data for SSH bruteforce detection...")
        
        if self.config['data_source'] == 'beth':
            logger.info("Downloading BETH dataset...")
            downloader = DatasetDownloader(str(self.data_dir))
            if downloader.setup_kaggle_api():
                if downloader.download_dataset('beth'):
                    ssh_data = downloader.prepare_ssh_data('beth')
                    if ssh_data is not None:
                        return ssh_data
            
            logger.warning("Failed to download BETH dataset, using sample data")
            self.config['data_source'] = 'sample'
        
        if self.config['data_source'] == 'sample':
            logger.info("Generating sample SSH data...")
            return generate_sample_ssh_data(10000)
        
        elif self.config['data_source'] == 'file':
            file_path = self.config.get('data_file', 'data/ssh_logs.csv')
            logger.info(f"Loading data from {file_path}")
            return pd.read_csv(file_path)
        
        else:
            raise ValueError(f"Unknown data source: {self.config['data_source']}")
    
    def train_models(self, data):
        """Train detection models"""
        logger.info("Training SSH bruteforce detection models...")
        
        # Initialize main detector
        self.detector = SSHBruteforceDetector()
        
        # Preprocess data
        X, processed_df = self.detector.preprocess_data(data)
        y = self.detector.create_labels(processed_df)
        
        logger.info(f"Dataset shape: {X.shape}")
        logger.info(f"Bruteforce samples: {sum(y)} out of {len(y)} total")
        
        # Train main models
        X_test, y_test = self.detector.train_models(X, y)
        
        # Save main model
        main_model_path = self.models_dir / 'ssh_bruteforce_models.pkl'
        self.detector.save_models(str(main_model_path))
        
        # Train additional models if requested
        additional_models = {}
        
        if 'neural_network' in self.config['model_types']:
            logger.info("Training neural network models...")
            try:
                nn_models, nn_results = train_ensemble_models(X, y)
                additional_models.update(nn_models)
            except Exception as e:
                logger.error(f"Failed to train neural networks: {e}")
        
        # Store models for evaluation
        self.models = {
            'Random Forest': self.detector.rf_model,
            'Neural Network': self.detector.nn_model,
            **additional_models
        }
        
        return X_test, y_test
    
    def evaluate_system(self, X_test, y_test):
        """Evaluate the detection system"""
        if not self.config['evaluation_enabled']:
            logger.info("Evaluation disabled in config")
            return None
        
        logger.info("Evaluating SSH detection system...")
        
        try:
            evaluator, comparison_df, report = evaluate_ssh_detection_system(
                self.models, X_test, y_test
            )
            
            # Save evaluation report
            report_file = self.reports_dir / f'evaluation_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            evaluator.generate_evaluation_report(str(report_file))
            
            logger.info(f"Evaluation report saved to: {report_file}")
            return evaluator, comparison_df, report
            
        except Exception as e:
            logger.error(f"Evaluation failed: {e}")
            return None
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if not self.config['real_time_monitoring']:
            logger.info("Real-time monitoring disabled in config")
            return
        
        logger.info("Starting real-time SSH monitoring...")
        
        # Load trained model
        model_path = self.models_dir / 'ssh_bruteforce_models.pkl'
        if not model_path.exists():
            logger.error("No trained model found. Please train models first.")
            return
        
        try:
            self.monitor = RealTimeSSHMonitor(str(model_path))
            self.monitor.start_monitoring()
            
            # Setup automated response if enabled
            if self.config['automated_response']:
                self.response_manager = ThreatResponseManager()
            
            logger.info("Real-time monitoring started successfully")
            return self.monitor
            
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            return None
    
    def run_demo(self):
        """Run a complete demonstration of the system"""
        logger.info("🚀 Starting SSH Bruteforce Detection System Demo")
        print("=" * 60)
        print("SSH BRUTEFORCE DETECTION SYSTEM")
        print("AI-Based Real-Time Threat Analysis")
        print("=" * 60)
        
        try:
            # Step 1: Setup data
            print("\n📊 Step 1: Setting up data...")
            data = self.setup_data()
            print(f"✅ Data loaded: {len(data)} records")
            
            # Step 2: Train models
            print("\n🤖 Step 2: Training detection models...")
            X_test, y_test = self.train_models(data)
            print("✅ Models trained successfully")
            
            # Step 3: Evaluate system
            print("\n📈 Step 3: Evaluating system performance...")
            evaluation_results = self.evaluate_system(X_test, y_test)
            if evaluation_results:
                print("✅ Evaluation completed")
            
            # Step 4: Demonstrate real-time detection
            print("\n🔍 Step 4: Demonstrating real-time detection...")
            self.demo_realtime_detection()
            
            # Step 5: Show automated response
            if self.config['automated_response']:
                print("\n🔒 Step 5: Demonstrating automated response...")
                self.demo_automated_response()
            
            print("\n✅ Demo completed successfully!")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            print(f"❌ Demo failed: {e}")
    
    def demo_realtime_detection(self):
        """Demonstrate real-time detection capabilities"""
        if self.detector is None:
            logger.error("No trained detector available")
            return
        
        # Sample log entries for demonstration
        sample_logs = [
            {
                'timestamp': pd.Timestamp.now(),
                'source_ip': '203.0.113.50',  # Suspicious IP
                'username': 'admin',
                'event_type': 'failed_login',
                'port': 22
            },
            {
                'timestamp': pd.Timestamp.now(),
                'source_ip': '203.0.113.50',  # Same suspicious IP
                'username': 'root',
                'event_type': 'failed_login',
                'port': 22
            },
            {
                'timestamp': pd.Timestamp.now(),
                'source_ip': '192.168.1.50',  # Normal IP
                'username': 'alice',
                'event_type': 'successful_login',
                'port': 22
            }
        ]
        
        print("   Analyzing sample SSH log entries...")
        for i, log in enumerate(sample_logs):
            try:
                result = self.detector.predict_realtime(log)
                
                threat_level = "🔴 HIGH" if result['bruteforce_probability'] > 0.7 else \
                              "🟡 MEDIUM" if result['bruteforce_probability'] > 0.3 else \
                              "🟢 LOW"
                
                print(f"\n   📝 Log Entry {i+1}:")
                print(f"      Source: {log['source_ip']}")
                print(f"      User: {log['username']}")
                print(f"      Event: {log['event_type']}")
                print(f"      Threat Level: {threat_level}")
                print(f"      Probability: {result['bruteforce_probability']:.2%}")
                print(f"      Classification: {'⚠️ ATTACK' if result['is_bruteforce'] else '✅ NORMAL'}")
                
            except Exception as e:
                print(f"   ❌ Error processing log entry: {e}")
    
    def demo_automated_response(self):
        """Demonstrate automated response system"""
        print("   Simulating automated threat responses...")
        
        if self.response_manager is None:
            self.response_manager = ThreatResponseManager()
        
        # Simulate high-threat alert
        alert = {
            'source_ip': '203.0.113.50',
            'probability': 0.95,
            'threat_type': 'ssh_bruteforce',
            'username': 'admin',
            'total_attempts': 20,
            'timestamp': datetime.now()
        }
        
        actions = self.response_manager.process_threat_alert(alert)
        print(f"   🔧 Response actions: {', '.join(actions)}")
        
        # Show dashboard data
        dashboard = self.response_manager.get_dashboard_data()
        print(f"   📊 Threats detected: {dashboard['active_threats']}")
        print(f"   🚫 IPs blocked: {len(dashboard['blocked_ips'])}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='SSH Bruteforce Detection System')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--mode', '-m', choices=['train', 'monitor', 'demo', 'evaluate'], 
                       default='demo', help='Operation mode')
    parser.add_argument('--data-source', '-d', choices=['sample', 'beth', 'file'],
                       help='Data source for training')
    parser.add_argument('--data-file', '-f', help='Data file path (for file mode)')
    parser.add_argument('--no-evaluation', action='store_true', 
                       help='Skip model evaluation')
    parser.add_argument('--enable-monitoring', action='store_true',
                       help='Enable real-time monitoring')
    parser.add_argument('--enable-response', action='store_true',
                       help='Enable automated response')
    
    args = parser.parse_args()
    
    # Create system with configuration
    system = SSHDetectionSystem(args.config)
    
    # Override config with command line arguments
    if args.data_source:
        system.config['data_source'] = args.data_source
    if args.data_file:
        system.config['data_file'] = args.data_file
    if args.no_evaluation:
        system.config['evaluation_enabled'] = False
    if args.enable_monitoring:
        system.config['real_time_monitoring'] = True
    if args.enable_response:
        system.config['automated_response'] = True
    
    # Execute based on mode
    if args.mode == 'demo':
        system.run_demo()
    
    elif args.mode == 'train':
        logger.info("Training models...")
        data = system.setup_data()
        system.train_models(data)
        logger.info("Training completed")
    
    elif args.mode == 'monitor':
        logger.info("Starting monitoring mode...")
        monitor = system.start_monitoring()
        if monitor:
            try:
                # Keep monitoring running
                import time
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                monitor.stop_monitoring()
    
    elif args.mode == 'evaluate':
        logger.info("Evaluation mode...")
        data = system.setup_data()
        X_test, y_test = system.train_models(data)
        system.evaluate_system(X_test, y_test)

if __name__ == "__main__":
    main()
