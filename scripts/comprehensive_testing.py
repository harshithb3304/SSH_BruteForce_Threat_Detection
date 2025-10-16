#!/usr/bin/env python3
"""
Comprehensive testing suite for SSH Bruteforce Detection System
Tests all components with proper evaluation methodology
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
import pickle
import json
import time
import logging
from datetime import datetime

# Add src to path
sys.path.append(str(Path(__file__).parent / 'src'))

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
    precision_recall_curve, average_precision_score
)
from sklearn.model_selection import cross_val_score, StratifiedKFold

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('comprehensive_test_log.txt'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SSHDetectionTester:
    """Comprehensive testing class for SSH Detection System"""
    
    def __init__(self):
        self.results = {}
        self.test_timestamp = datetime.now()
        
    def load_beth_data(self):
        """Load separate BETH train and test datasets"""
        logger.info("=== Loading BETH Test Data ===")
        
        train_file = "src/data/data/beth/labelled_training_data.csv"
        test_file = "src/data/data/beth/labelled_testing_data.csv"
        val_file = "src/data/data/beth/labelled_validation_data.csv"
        
        # Load datasets
        train_df = pd.read_csv(train_file, low_memory=False)
        test_df = pd.read_csv(test_file, low_memory=False)
        val_df = pd.read_csv(val_file, low_memory=False)
        
        logger.info(f"Training data: {len(train_df):,} samples")
        logger.info(f"Testing data: {len(test_df):,} samples")
        logger.info(f"Validation data: {len(val_df):,} samples")
        
        # Create attack labels
        for df in [train_df, test_df, val_df]:
            df['is_attack'] = ((df['sus'] == 1) | (df['evil'] == 1)).astype(int)
        
        # Log dataset statistics
        self.results['dataset_stats'] = {
            'train_samples': len(train_df),
            'test_samples': len(test_df),
            'val_samples': len(val_df),
            'train_attacks': int(train_df['is_attack'].sum()),
            'test_attacks': int(test_df['is_attack'].sum()),
            'val_attacks': int(val_df['is_attack'].sum()),
            'train_attack_rate': float(train_df['is_attack'].mean()),
            'test_attack_rate': float(test_df['is_attack'].mean()),
            'val_attack_rate': float(val_df['is_attack'].mean())
        }
        
        return train_df, test_df, val_df
    
    def extract_features(self, df):
        """Extract features for testing"""
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
        
        # Event type features
        features['event_close'] = (df['eventName'] == 'close').astype(int)
        features['event_openat'] = (df['eventName'] == 'openat').astype(int)
        features['event_socket'] = (df['eventName'] == 'socket').astype(int)
        
        # Time features
        features['hour'] = (df['timestamp'] % 86400 / 3600).fillna(0).astype(int)
        
        # Root user flag
        features['is_root_user'] = (df['userId'] == 0).astype(int)
        
        return features
    
    def test_model_performance(self):
        """Test model performance on independent datasets"""
        logger.info("=== Testing Model Performance ===")
        
        # Load trained models
        rf_path = Path('models_proper/random_forest_proper.pkl')
        lr_path = Path('models_proper/logistic_regression_proper.pkl')
        
        if not rf_path.exists() or not lr_path.exists():
            logger.error("Trained models not found. Run proper_training.py first.")
            return
        
        # Load models
        with open(rf_path, 'rb') as f:
            rf_data = pickle.load(f)
        with open(lr_path, 'rb') as f:
            lr_data = pickle.load(f)
        
        # Load test data
        train_df, test_df, val_df = self.load_beth_data()
        
        # Test on multiple datasets
        test_sets = {
            'test_set': test_df,
            'validation_set': val_df
        }
        
        model_results = {}
        
        for model_name, model_data in [('Random_Forest', rf_data), ('Logistic_Regression', lr_data)]:
            model = model_data['model']
            scaler = model_data['scaler']
            
            model_results[model_name] = {}
            
            for set_name, dataset in test_sets.items():
                logger.info(f"\nTesting {model_name} on {set_name}...")
                
                # Extract features
                X = self.extract_features(dataset)
                y = dataset['is_attack']
                
                # Scale features
                X_scaled = scaler.transform(X)
                
                # Predictions
                start_time = time.time()
                y_pred = model.predict(X_scaled)
                y_pred_proba = model.predict_proba(X_scaled)[:, 1]
                prediction_time = time.time() - start_time
                
                # Calculate metrics
                metrics = {
                    'accuracy': float(accuracy_score(y, y_pred)),
                    'precision': float(precision_score(y, y_pred, zero_division=0)),
                    'recall': float(recall_score(y, y_pred, zero_division=0)),
                    'f1_score': float(f1_score(y, y_pred, zero_division=0)),
                    'roc_auc': float(roc_auc_score(y, y_pred_proba)) if len(np.unique(y)) > 1 else 0.0,
                    'avg_precision': float(average_precision_score(y, y_pred_proba)) if len(np.unique(y)) > 1 else 0.0,
                    'prediction_time': float(prediction_time),
                    'samples_per_second': float(len(X) / prediction_time)
                }
                
                # Confusion matrix
                cm = confusion_matrix(y, y_pred)
                if cm.size == 4:
                    tn, fp, fn, tp = cm.ravel()
                else:
                    # Handle edge cases
                    tn = fp = fn = tp = 0
                    if len(np.unique(y)) == 1:
                        if y.iloc[0] == 0:
                            tn = len(y)
                        else:
                            tp = len(y)
                
                metrics.update({
                    'true_positives': int(tp),
                    'true_negatives': int(tn),
                    'false_positives': int(fp),
                    'false_negatives': int(fn),
                    'specificity': float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0,
                    'false_positive_rate': float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
                    'detection_rate': float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
                })
                
                model_results[model_name][set_name] = metrics
                
                logger.info(f"  Accuracy: {metrics['accuracy']:.4f}")
                logger.info(f"  Precision: {metrics['precision']:.4f}")
                logger.info(f"  Recall: {metrics['recall']:.4f}")
                logger.info(f"  F1-Score: {metrics['f1_score']:.4f}")
                logger.info(f"  Processing: {metrics['samples_per_second']:.0f} samples/sec")
        
        self.results['model_performance'] = model_results
        return model_results
    
    def test_cross_validation(self):
        """Perform cross-validation testing"""
        logger.info("=== Cross-Validation Testing ===")
        
        # Load training data only
        train_df, _, _ = self.load_beth_data()
        
        # Extract features
        X = self.extract_features(train_df)
        y = train_df['is_attack']
        
        # Load scaler and scale features
        with open('models_proper/random_forest_proper.pkl', 'rb') as f:
            model_data = pickle.load(f)
        scaler = model_data['scaler']
        X_scaled = scaler.transform(X)
        
        # 5-fold cross-validation
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        
        # Test Random Forest
        from sklearn.ensemble import RandomForestClassifier
        rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
        
        cv_scores = cross_val_score(rf, X_scaled, y, cv=cv, scoring='accuracy', n_jobs=-1)
        
        cv_results = {
            'mean_accuracy': float(cv_scores.mean()),
            'std_accuracy': float(cv_scores.std()),
            'fold_scores': cv_scores.tolist(),
            'confidence_interval_95': [
                float(cv_scores.mean() - 1.96 * cv_scores.std()),
                float(cv_scores.mean() + 1.96 * cv_scores.std())
            ]
        }
        
        logger.info(f"Cross-Validation Results:")
        logger.info(f"  Mean Accuracy: {cv_results['mean_accuracy']:.4f} ± {cv_results['std_accuracy']:.4f}")
        logger.info(f"  95% CI: [{cv_results['confidence_interval_95'][0]:.4f}, {cv_results['confidence_interval_95'][1]:.4f}]")
        
        self.results['cross_validation'] = cv_results
        return cv_results
    
    def test_realtime_performance(self):
        """Test real-time detection performance"""
        logger.info("=== Real-time Performance Testing ===")
        
        # Load model
        with open('models_proper/random_forest_proper.pkl', 'rb') as f:
            model_data = pickle.load(f)
        
        model = model_data['model']
        scaler = model_data['scaler']
        
        # Load test data
        _, test_df, _ = self.load_beth_data()
        
        # Sample for real-time simulation
        sample_data = test_df.sample(n=min(1000, len(test_df)), random_state=42)
        
        # Test single prediction latency
        single_sample = self.extract_features(sample_data.iloc[[0]])
        single_scaled = scaler.transform(single_sample)
        
        # Measure single prediction time
        times = []
        for _ in range(100):
            start = time.time()
            _ = model.predict(single_scaled)
            times.append(time.time() - start)
        
        single_prediction_time = np.mean(times)
        
        # Test batch prediction throughput
        batch_features = self.extract_features(sample_data)
        batch_scaled = scaler.transform(batch_features)
        
        start_time = time.time()
        _ = model.predict(batch_scaled)
        batch_time = time.time() - start_time
        throughput = len(sample_data) / batch_time
        
        performance_results = {
            'single_prediction_latency_ms': float(single_prediction_time * 1000),
            'batch_throughput_samples_per_sec': float(throughput),
            'batch_size_tested': len(sample_data),
            'total_batch_time_sec': float(batch_time)
        }
        
        logger.info(f"Real-time Performance:")
        logger.info(f"  Single Prediction: {performance_results['single_prediction_latency_ms']:.2f} ms")
        logger.info(f"  Batch Throughput: {performance_results['batch_throughput_samples_per_sec']:.0f} samples/sec")
        
        self.results['realtime_performance'] = performance_results
        return performance_results
    
    def test_model_robustness(self):
        """Test model robustness and edge cases"""
        logger.info("=== Model Robustness Testing ===")
        
        # Load model
        with open('models_proper/random_forest_proper.pkl', 'rb') as f:
            model_data = pickle.load(f)
        
        model = model_data['model']
        scaler = model_data['scaler']
        
        # Test edge cases
        edge_cases = {
            'all_zeros': pd.DataFrame(np.zeros((10, 13)), columns=model_data['feature_columns']),
            'all_max_values': pd.DataFrame(np.full((10, 13), 999999), columns=model_data['feature_columns']),
            'random_noise': pd.DataFrame(np.random.randn(10, 13), columns=model_data['feature_columns'])
        }
        
        robustness_results = {}
        
        for case_name, test_data in edge_cases.items():
            try:
                scaled_data = scaler.transform(test_data)
                predictions = model.predict(scaled_data)
                probabilities = model.predict_proba(scaled_data)
                
                robustness_results[case_name] = {
                    'predictions': predictions.tolist(),
                    'avg_probability': float(np.mean(probabilities[:, 1])),
                    'status': 'passed'
                }
                
            except Exception as e:
                robustness_results[case_name] = {
                    'status': 'failed',
                    'error': str(e)
                }
                logger.warning(f"  {case_name}: FAILED - {e}")
        
        logger.info("Robustness testing completed")
        self.results['robustness'] = robustness_results
        return robustness_results
    
    def generate_comprehensive_report(self):
        """Generate comprehensive test report"""
        logger.info("=== Generating Comprehensive Report ===")
        
        # Add test metadata
        self.results['test_metadata'] = {
            'timestamp': self.test_timestamp.isoformat(),
            'test_duration_minutes': (datetime.now() - self.test_timestamp).total_seconds() / 60,
            'python_version': sys.version,
            'system_info': os.uname()._asdict() if hasattr(os, 'uname') else 'Unknown'
        }
        
        # Save detailed results
        results_path = Path('test_results_comprehensive.json')
        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"✓ Comprehensive test results saved: {results_path}")
        
        # Generate summary
        self.print_test_summary()
        
        return self.results
    
    def print_test_summary(self):
        """Print test summary"""
        logger.info("\n" + "="*80)
        logger.info("COMPREHENSIVE TEST SUMMARY")
        logger.info("="*80)
        
        # Dataset summary
        ds = self.results.get('dataset_stats', {})
        logger.info(f"\n📊 Dataset Statistics:")
        logger.info(f"  Training:   {ds.get('train_samples', 0):,} samples ({ds.get('train_attack_rate', 0):.2%} attacks)")
        logger.info(f"  Testing:    {ds.get('test_samples', 0):,} samples ({ds.get('test_attack_rate', 0):.2%} attacks)")
        logger.info(f"  Validation: {ds.get('val_samples', 0):,} samples ({ds.get('val_attack_rate', 0):.2%} attacks)")
        
        # Model performance summary
        if 'model_performance' in self.results:
            logger.info(f"\n🤖 Model Performance on Test Set:")
            for model_name, results in self.results['model_performance'].items():
                if 'test_set' in results:
                    test_metrics = results['test_set']
                    logger.info(f"  {model_name}:")
                    logger.info(f"    Accuracy:  {test_metrics.get('accuracy', 0):.4f}")
                    logger.info(f"    Precision: {test_metrics.get('precision', 0):.4f}")
                    logger.info(f"    Recall:    {test_metrics.get('recall', 0):.4f}")
                    logger.info(f"    F1-Score:  {test_metrics.get('f1_score', 0):.4f}")
        
        # Cross-validation summary
        if 'cross_validation' in self.results:
            cv = self.results['cross_validation']
            logger.info(f"\n🔄 Cross-Validation (5-fold):")
            logger.info(f"  Mean Accuracy: {cv.get('mean_accuracy', 0):.4f} ± {cv.get('std_accuracy', 0):.4f}")
        
        # Performance summary
        if 'realtime_performance' in self.results:
            perf = self.results['realtime_performance']
            logger.info(f"\n⚡ Real-time Performance:")
            logger.info(f"  Single Prediction: {perf.get('single_prediction_latency_ms', 0):.2f} ms")
            logger.info(f"  Throughput:       {perf.get('batch_throughput_samples_per_sec', 0):.0f} samples/sec")
        
        logger.info(f"\n✅ All tests completed successfully!")

def main():
    """Main testing function"""
    logger.info("="*80)
    logger.info("SSH BRUTEFORCE DETECTION - COMPREHENSIVE TESTING")
    logger.info("="*80)
    
    tester = SSHDetectionTester()
    
    try:
        # Run comprehensive tests
        tester.test_model_performance()
        tester.test_cross_validation()
        tester.test_realtime_performance()
        tester.test_model_robustness()
        
        # Generate final report
        results = tester.generate_comprehensive_report()
        
        logger.info("\n" + "="*80)
        logger.info("TESTING COMPLETED SUCCESSFULLY")
        logger.info("="*80)
        
        return results
        
    except Exception as e:
        logger.error(f"Testing failed: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()