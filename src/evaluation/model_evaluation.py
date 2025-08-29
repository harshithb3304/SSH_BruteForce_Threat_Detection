#!/usr/bin/env python3
"""
Comprehensive evaluation module for SSH bruteforce detection system
Provides detailed performance metrics and visualization
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve,
    precision_recall_curve, average_precision_score
)
from sklearn.model_selection import cross_val_score, StratifiedKFold
import time
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class ModelEvaluator:
    """
    Comprehensive evaluation class for SSH bruteforce detection models
    """
    
    def __init__(self):
        self.results = {}
        self.plots = {}
        
    def evaluate_model(self, model, X_test, y_test, model_name="Model"):
        """
        Comprehensive evaluation of a single model
        """
        print(f"\n{'='*60}")
        print(f"EVALUATING {model_name.upper()}")
        print(f"{'='*60}")
        
        # Make predictions
        start_time = time.time()
        
        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X_test)[:, 1]
        elif hasattr(model, 'decision_function'):
            y_pred_proba = model.decision_function(X_test)
        else:
            y_pred_proba = model.predict(X_test)
            if len(y_pred_proba.shape) > 1:
                y_pred_proba = y_pred_proba[:, 1] if y_pred_proba.shape[1] > 1 else y_pred_proba.flatten()
        
        y_pred = (y_pred_proba > 0.5).astype(int)
        prediction_time = time.time() - start_time
        
        # Calculate metrics
        metrics = self._calculate_metrics(y_test, y_pred, y_pred_proba)
        metrics['prediction_time'] = prediction_time
        metrics['predictions_per_second'] = len(y_test) / prediction_time
        
        # Store results
        self.results[model_name] = {
            'metrics': metrics,
            'y_true': y_test,
            'y_pred': y_pred,
            'y_pred_proba': y_pred_proba
        }
        
        # Print results
        self._print_metrics(metrics, model_name)
        
        return metrics
    
    def _calculate_metrics(self, y_true, y_pred, y_pred_proba):
        """
        Calculate comprehensive performance metrics
        """
        metrics = {}
        
        # Basic classification metrics
        metrics['accuracy'] = accuracy_score(y_true, y_pred)
        metrics['precision'] = precision_score(y_true, y_pred, zero_division=0)
        metrics['recall'] = recall_score(y_true, y_pred, zero_division=0)
        metrics['f1_score'] = f1_score(y_true, y_pred, zero_division=0)
        
        # ROC metrics
        if len(np.unique(y_true)) > 1:
            metrics['roc_auc'] = roc_auc_score(y_true, y_pred_proba)
            metrics['average_precision'] = average_precision_score(y_true, y_pred_proba)
        else:
            metrics['roc_auc'] = 0.0
            metrics['average_precision'] = 0.0
        
        # Confusion matrix components
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        metrics['true_negatives'] = tn
        metrics['false_positives'] = fp
        metrics['false_negatives'] = fn
        metrics['true_positives'] = tp
        
        # Additional metrics
        metrics['specificity'] = tn / (tn + fp) if (tn + fp) > 0 else 0
        metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0
        metrics['false_negative_rate'] = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        # Detection metrics (specific to security applications)
        metrics['detection_rate'] = tp / (tp + fn) if (tp + fn) > 0 else 0  # Same as recall
        metrics['false_alarm_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0  # Same as FPR
        
        return metrics
    
    def _print_metrics(self, metrics, model_name):
        """
        Print formatted metrics
        """
        print(f"\n📊 {model_name} Performance Metrics:")
        print("-" * 40)
        print(f"Accuracy:      {metrics['accuracy']:.4f}")
        print(f"Precision:     {metrics['precision']:.4f}")
        print(f"Recall:        {metrics['recall']:.4f}")
        print(f"F1-Score:      {metrics['f1_score']:.4f}")
        print(f"ROC-AUC:       {metrics['roc_auc']:.4f}")
        print(f"Avg Precision: {metrics['average_precision']:.4f}")
        print(f"Specificity:   {metrics['specificity']:.4f}")
        
        print(f"\n🔍 Detection Performance:")
        print(f"Detection Rate:     {metrics['detection_rate']:.4f}")
        print(f"False Alarm Rate:   {metrics['false_alarm_rate']:.4f}")
        
        print(f"\n⚡ Performance:")
        print(f"Prediction Time:    {metrics['prediction_time']:.4f} seconds")
        print(f"Predictions/sec:    {metrics['predictions_per_second']:.0f}")
        
        print(f"\n📈 Confusion Matrix:")
        print(f"True Positives:     {metrics['true_positives']}")
        print(f"True Negatives:     {metrics['true_negatives']}")
        print(f"False Positives:    {metrics['false_positives']}")
        print(f"False Negatives:    {metrics['false_negatives']}")
    
    def compare_models(self):
        """
        Compare multiple models and create comparison visualizations
        """
        if len(self.results) < 2:
            print("Need at least 2 models for comparison")
            return
        
        print(f"\n{'='*60}")
        print("MODEL COMPARISON")
        print(f"{'='*60}")
        
        # Create comparison DataFrame
        comparison_data = []
        for model_name, result in self.results.items():
            metrics = result['metrics']
            comparison_data.append({
                'Model': model_name,
                'Accuracy': metrics['accuracy'],
                'Precision': metrics['precision'],
                'Recall': metrics['recall'],
                'F1-Score': metrics['f1_score'],
                'ROC-AUC': metrics['roc_auc'],
                'Detection Rate': metrics['detection_rate'],
                'False Alarm Rate': metrics['false_alarm_rate'],
                'Pred/sec': metrics['predictions_per_second']
            })
        
        df_comparison = pd.DataFrame(comparison_data)
        print("\n📊 Model Comparison Table:")
        print(df_comparison.round(4).to_string(index=False))
        
        # Create comparison plots
        self._create_comparison_plots(df_comparison)
        
        # Find best model
        best_model = self._find_best_model()
        print(f"\n🏆 Best Model: {best_model['name']}")
        print(f"   Based on F1-Score: {best_model['f1_score']:.4f}")
        
        return df_comparison
    
    def _find_best_model(self):
        """
        Find the best performing model based on F1-score
        """
        best_f1 = 0
        best_model_name = ""
        
        for model_name, result in self.results.items():
            f1 = result['metrics']['f1_score']
            if f1 > best_f1:
                best_f1 = f1
                best_model_name = model_name
        
        return {
            'name': best_model_name,
            'f1_score': best_f1,
            'metrics': self.results[best_model_name]['metrics']
        }
    
    def _create_comparison_plots(self, df_comparison):
        """
        Create comparison visualizations
        """
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # Metrics comparison
        metrics_to_plot = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC']
        df_metrics = df_comparison[['Model'] + metrics_to_plot].set_index('Model')
        
        df_metrics.plot(kind='bar', ax=axes[0, 0], width=0.8)
        axes[0, 0].set_title('Model Performance Comparison')
        axes[0, 0].set_ylabel('Score')
        axes[0, 0].legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        axes[0, 0].tick_params(axis='x', rotation=45)
        
        # ROC curves
        axes[0, 1].set_title('ROC Curves Comparison')
        for model_name, result in self.results.items():
            if result['metrics']['roc_auc'] > 0:
                fpr, tpr, _ = roc_curve(result['y_true'], result['y_pred_proba'])
                axes[0, 1].plot(fpr, tpr, label=f"{model_name} (AUC: {result['metrics']['roc_auc']:.3f})")
        
        axes[0, 1].plot([0, 1], [0, 1], 'k--', alpha=0.5)
        axes[0, 1].set_xlabel('False Positive Rate')
        axes[0, 1].set_ylabel('True Positive Rate')
        axes[0, 1].legend()
        
        # Precision-Recall curves
        axes[1, 0].set_title('Precision-Recall Curves')
        for model_name, result in self.results.items():
            if result['metrics']['roc_auc'] > 0:
                precision, recall, _ = precision_recall_curve(result['y_true'], result['y_pred_proba'])
                axes[1, 0].plot(recall, precision, label=f"{model_name} (AP: {result['metrics']['average_precision']:.3f})")
        
        axes[1, 0].set_xlabel('Recall')
        axes[1, 0].set_ylabel('Precision')
        axes[1, 0].legend()
        
        # Performance vs Speed
        axes[1, 1].scatter(df_comparison['Pred/sec'], df_comparison['F1-Score'])
        for i, model in enumerate(df_comparison['Model']):
            axes[1, 1].annotate(model, 
                              (df_comparison.iloc[i]['Pred/sec'], df_comparison.iloc[i]['F1-Score']),
                              xytext=(5, 5), textcoords='offset points')
        axes[1, 1].set_xlabel('Predictions per Second')
        axes[1, 1].set_ylabel('F1-Score')
        axes[1, 1].set_title('Performance vs Speed')
        
        plt.tight_layout()
        plt.savefig('model_comparison.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def create_confusion_matrices(self):
        """
        Create confusion matrix visualizations for all models
        """
        n_models = len(self.results)
        cols = min(3, n_models)
        rows = (n_models + cols - 1) // cols
        
        fig, axes = plt.subplots(rows, cols, figsize=(5*cols, 4*rows))
        if n_models == 1:
            axes = [axes]
        elif rows == 1:
            axes = axes.reshape(1, -1)
        
        for idx, (model_name, result) in enumerate(self.results.items()):
            row = idx // cols
            col = idx % cols
            ax = axes[row, col] if rows > 1 else axes[col]
            
            cm = confusion_matrix(result['y_true'], result['y_pred'])
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax)
            ax.set_title(f'{model_name}\nConfusion Matrix')
            ax.set_xlabel('Predicted')
            ax.set_ylabel('Actual')
        
        # Hide empty subplots
        for idx in range(n_models, rows * cols):
            row = idx // cols
            col = idx % cols
            ax = axes[row, col] if rows > 1 else axes[col]
            ax.set_visible(False)
        
        plt.tight_layout()
        plt.savefig('confusion_matrices.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def analyze_detection_performance(self):
        """
        Analyze detection performance specific to cybersecurity
        """
        print(f"\n{'='*60}")
        print("CYBERSECURITY DETECTION ANALYSIS")
        print(f"{'='*60}")
        
        for model_name, result in self.results.items():
            metrics = result['metrics']
            
            print(f"\n🔒 {model_name} Security Analysis:")
            print("-" * 40)
            
            # Critical security metrics
            detection_rate = metrics['detection_rate']
            false_alarm_rate = metrics['false_alarm_rate']
            
            print(f"Detection Rate (Sensitivity): {detection_rate:.4f}")
            print(f"False Alarm Rate:            {false_alarm_rate:.4f}")
            
            # Security effectiveness rating
            if detection_rate > 0.9 and false_alarm_rate < 0.05:
                rating = "EXCELLENT"
            elif detection_rate > 0.8 and false_alarm_rate < 0.1:
                rating = "GOOD"
            elif detection_rate > 0.7 and false_alarm_rate < 0.2:
                rating = "ACCEPTABLE"
            else:
                rating = "NEEDS IMPROVEMENT"
            
            print(f"Security Effectiveness:      {rating}")
            
            # Attack detection analysis
            total_attacks = metrics['true_positives'] + metrics['false_negatives']
            detected_attacks = metrics['true_positives']
            missed_attacks = metrics['false_negatives']
            
            print(f"\n📊 Attack Detection Analysis:")
            print(f"Total Attacks:     {total_attacks}")
            print(f"Detected Attacks:  {detected_attacks}")
            print(f"Missed Attacks:    {missed_attacks}")
            
            if total_attacks > 0:
                miss_rate = missed_attacks / total_attacks
                print(f"Attack Miss Rate:  {miss_rate:.4f}")
            
            # False positive analysis
            total_normal = metrics['true_negatives'] + metrics['false_positives']
            false_alarms = metrics['false_positives']
            
            print(f"\n🚨 False Alert Analysis:")
            print(f"Total Normal Traffic: {total_normal}")
            print(f"False Alarms:        {false_alarms}")
            
            if total_normal > 0:
                false_alarm_percentage = (false_alarms / total_normal) * 100
                print(f"False Alarm %:       {false_alarm_percentage:.2f}%")
    
    def generate_evaluation_report(self, output_file='evaluation_report.json'):
        """
        Generate comprehensive evaluation report
        """
        report = {
            'evaluation_timestamp': datetime.now().isoformat(),
            'models_evaluated': len(self.results),
            'model_results': {}
        }
        
        for model_name, result in self.results.items():
            model_report = {
                'metrics': result['metrics'],
                'performance_summary': {
                    'accuracy': result['metrics']['accuracy'],
                    'f1_score': result['metrics']['f1_score'],
                    'detection_rate': result['metrics']['detection_rate'],
                    'false_alarm_rate': result['metrics']['false_alarm_rate']
                }
            }
            report['model_results'][model_name] = model_report
        
        # Add best model recommendation
        best_model = self._find_best_model()
        report['recommendation'] = {
            'best_model': best_model['name'],
            'best_f1_score': best_model['f1_score'],
            'justification': f"Highest F1-score of {best_model['f1_score']:.4f}"
        }
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Evaluation report saved to: {output_file}")
        return report
    
    def cross_validate_model(self, model, X, y, cv_folds=5):
        """
        Perform cross-validation on a model
        """
        print(f"\n🔄 Performing {cv_folds}-Fold Cross-Validation...")
        
        skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        
        # Cross-validation scores
        cv_scores = {
            'accuracy': cross_val_score(model, X, y, cv=skf, scoring='accuracy'),
            'precision': cross_val_score(model, X, y, cv=skf, scoring='precision'),
            'recall': cross_val_score(model, X, y, cv=skf, scoring='recall'),
            'f1': cross_val_score(model, X, y, cv=skf, scoring='f1'),
            'roc_auc': cross_val_score(model, X, y, cv=skf, scoring='roc_auc')
        }
        
        print("\n📊 Cross-Validation Results:")
        print("-" * 30)
        for metric, scores in cv_scores.items():
            print(f"{metric.capitalize()}: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")
        
        return cv_scores

def evaluate_ssh_detection_system(models, X_test, y_test):
    """
    Main function to evaluate SSH bruteforce detection system
    """
    evaluator = ModelEvaluator()
    
    print("🔍 SSH BRUTEFORCE DETECTION SYSTEM EVALUATION")
    print("=" * 60)
    
    # Evaluate each model
    for model_name, model in models.items():
        evaluator.evaluate_model(model, X_test, y_test, model_name)
    
    # Create comparison
    comparison_df = evaluator.compare_models()
    
    # Create confusion matrices
    evaluator.create_confusion_matrices()
    
    # Security-specific analysis
    evaluator.analyze_detection_performance()
    
    # Generate report
    report = evaluator.generate_evaluation_report()
    
    return evaluator, comparison_df, report

if __name__ == "__main__":
    # Example usage with synthetic data
    from sklearn.datasets import make_classification
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    
    # Generate sample data
    X, y = make_classification(n_samples=1000, n_features=20, n_redundant=5,
                             n_informative=15, random_state=42, n_clusters_per_class=1)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train sample models
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
        'Logistic Regression': LogisticRegression(random_state=42)
    }
    
    for name, model in models.items():
        model.fit(X_train, y_train)
    
    # Evaluate
    evaluator, comparison, report = evaluate_ssh_detection_system(models, X_test, y_test)
    
    print("\n✅ Evaluation completed successfully!")
    print("📁 Generated files:")
    print("   - model_comparison.png")
    print("   - confusion_matrices.png") 
    print("   - evaluation_report.json")
