#!/usr/bin/env python3
"""
Neural Network models for SSH bruteforce detection
Implements various deep learning architectures
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Make TensorFlow and PyTorch imports optional
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    tf = None
    keras = None
    layers = None

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    PYTORCH_AVAILABLE = True
except ImportError:
    PYTORCH_AVAILABLE = False
    torch = None
    nn = None
    optim = None

if TENSORFLOW_AVAILABLE:
    class TensorFlowSSHDetector:
        """
        TensorFlow-based neural network for SSH bruteforce detection
        """
        
        def __init__(self, input_dim=None):
            self.input_dim = input_dim
            self.model = None
            self.scaler = StandardScaler()
            self.history = None
            
        def build_model(self, input_dim):
            """
            Build the neural network architecture
            """
            self.input_dim = input_dim
            
            # Create the model
            model = keras.Sequential([
                # Input layer
                layers.Dense(128, activation='relu', input_shape=(input_dim,)),
                layers.Dropout(0.3),
                
                # Hidden layers
                layers.Dense(64, activation='relu'),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                
                layers.Dense(32, activation='relu'),
                layers.Dropout(0.2),
                
                layers.Dense(16, activation='relu'),
                
                # Output layer
                layers.Dense(1, activation='sigmoid')
            ])
            
            # Compile the model
            model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=0.001),
                loss='binary_crossentropy',
                metrics=['accuracy', 'precision', 'recall']
            )
            
            self.model = model
            return model
        
        def train(self, X, y, validation_split=0.2, epochs=50, batch_size=32):
            """
            Train the neural network
            """
            if self.model is None:
                self.build_model(X.shape[1])
            
            # Scale the features
            X_scaled = self.scaler.fit_transform(X)
            
            # Early stopping callback
            early_stopping = keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            )
            
            # Reduce learning rate callback
            reduce_lr = keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.2,
                patience=5,
                min_lr=0.0001
            )
            
            # Train the model
            self.history = self.model.fit(
                X_scaled, y,
                validation_split=validation_split,
                epochs=epochs,
                batch_size=batch_size,
                callbacks=[early_stopping, reduce_lr],
                verbose=1
            )
            
            return self.history
        
        def predict(self, X):
            """
            Make predictions
            """
            X_scaled = self.scaler.transform(X)
            return self.model.predict(X_scaled)
        
        def evaluate(self, X_test, y_test):
            """
            Evaluate the model
            """
            X_test_scaled = self.scaler.transform(X_test)
            loss, accuracy, precision, recall = self.model.evaluate(X_test_scaled, y_test, verbose=0)
            
            # Predictions for additional metrics
            y_pred_proba = self.predict(X_test)
            y_pred = (y_pred_proba > 0.5).astype(int)
            
            print("Neural Network Model Evaluation:")
            print(f"Loss: {loss:.4f}")
            print(f"Accuracy: {accuracy:.4f}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall: {recall:.4f}")
            
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred))
            
            return {
                'loss': loss,
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'predictions': y_pred,
                'probabilities': y_pred_proba
            }
        
        def plot_training_history(self):
            """
            Plot training history
            """
            if self.history is None:
                print("No training history available")
                return
            
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            
            # Accuracy
            axes[0, 0].plot(self.history.history['accuracy'], label='Training Accuracy')
            axes[0, 0].plot(self.history.history['val_accuracy'], label='Validation Accuracy')
            axes[0, 0].set_title('Model Accuracy')
            axes[0, 0].set_xlabel('Epoch')
            axes[0, 0].set_ylabel('Accuracy')
            axes[0, 0].legend()
            
            # Loss
            axes[0, 1].plot(self.history.history['loss'], label='Training Loss')
            axes[0, 1].plot(self.history.history['val_loss'], label='Validation Loss')
            axes[0, 1].set_title('Model Loss')
            axes[0, 1].set_xlabel('Epoch')
            axes[0, 1].set_ylabel('Loss')
            axes[0, 1].legend()
            
            # Precision
            axes[1, 0].plot(self.history.history['precision'], label='Training Precision')
            axes[1, 0].plot(self.history.history['val_precision'], label='Validation Precision')
            axes[1, 0].set_title('Model Precision')
            axes[1, 0].set_xlabel('Epoch')
            axes[1, 0].set_ylabel('Precision')
            axes[1, 0].legend()
            
            # Recall
            axes[1, 1].plot(self.history.history['recall'], label='Training Recall')
            axes[1, 1].plot(self.history.history['val_recall'], label='Validation Recall')
            axes[1, 1].set_title('Model Recall')
            axes[1, 1].set_xlabel('Epoch')
            axes[1, 1].set_ylabel('Recall')
            axes[1, 1].legend()
            
            plt.tight_layout()
            plt.savefig('training_history.png', dpi=300, bbox_inches='tight')
            plt.show()
else:
    class TensorFlowSSHDetector:
        """Placeholder class when TensorFlow is not available"""
        def __init__(self, *args, **kwargs):
            raise ImportError("TensorFlow not available. Install with: pip install tensorflow")

if PYTORCH_AVAILABLE:
    class PyTorchSSHDetector(nn.Module):
        """
        PyTorch-based neural network for SSH bruteforce detection
        """
        
        def __init__(self, input_dim, hidden_dims=[128, 64, 32, 16]):
            super(PyTorchSSHDetector, self).__init__()
            
            self.layers = nn.ModuleList()
            
            # Input layer
            self.layers.append(nn.Linear(input_dim, hidden_dims[0]))
            self.layers.append(nn.ReLU())
            self.layers.append(nn.Dropout(0.3))
            
            # Hidden layers
            for i in range(len(hidden_dims) - 1):
                self.layers.append(nn.Linear(hidden_dims[i], hidden_dims[i + 1]))
                self.layers.append(nn.BatchNorm1d(hidden_dims[i + 1]))
                self.layers.append(nn.ReLU())
                self.layers.append(nn.Dropout(0.2))
            
            # Output layer
            self.layers.append(nn.Linear(hidden_dims[-1], 1))
            self.layers.append(nn.Sigmoid())
            
            self.scaler = StandardScaler()
            
        def forward(self, x):
            for layer in self.layers:
                if isinstance(layer, nn.BatchNorm1d) and x.size(0) == 1:
                    # Skip batch norm for single sample
                    continue
                x = layer(x)
            return x
        
        def train_model(self, X, y, epochs=100, batch_size=32, learning_rate=0.001):
            """
            Train the PyTorch model
            """
            # Prepare data
            X_scaled = self.scaler.fit_transform(X)
            X_train, X_val, y_train, y_val = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
            
            # Convert to tensors
            X_train_tensor = torch.FloatTensor(X_train)
            y_train_tensor = torch.FloatTensor(y_train).reshape(-1, 1)
            X_val_tensor = torch.FloatTensor(X_val)
            y_val_tensor = torch.FloatTensor(y_val).reshape(-1, 1)
            
            # Loss and optimizer
            criterion = nn.BCELoss()
            optimizer = optim.Adam(self.parameters(), lr=learning_rate)
            scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, 'min', patience=10)
            
            # Training loop
            train_losses = []
            val_losses = []
            train_accuracies = []
            val_accuracies = []
            
            for epoch in range(epochs):
                # Training
                self.train()
                train_loss = 0
                train_correct = 0
                
                for i in range(0, len(X_train_tensor), batch_size):
                    batch_X = X_train_tensor[i:i+batch_size]
                    batch_y = y_train_tensor[i:i+batch_size]
                    
                    optimizer.zero_grad()
                    outputs = self(batch_X)
                    loss = criterion(outputs, batch_y)
                    loss.backward()
                    optimizer.step()
                    
                    train_loss += loss.item()
                    train_correct += ((outputs > 0.5) == batch_y).float().sum().item()
                
                # Validation
                self.eval()
                with torch.no_grad():
                    val_outputs = self(X_val_tensor)
                    val_loss = criterion(val_outputs, y_val_tensor)
                    val_correct = ((val_outputs > 0.5) == y_val_tensor).float().sum().item()
                
                # Calculate metrics
                train_loss_avg = train_loss / (len(X_train_tensor) // batch_size + 1)
                val_loss_avg = val_loss.item()
                train_acc = train_correct / len(X_train_tensor)
                val_acc = val_correct / len(X_val_tensor)
                
                train_losses.append(train_loss_avg)
                val_losses.append(val_loss_avg)
                train_accuracies.append(train_acc)
                val_accuracies.append(val_acc)
                
                scheduler.step(val_loss_avg)
                
                if epoch % 10 == 0:
                    print(f'Epoch {epoch}/{epochs}: Train Loss: {train_loss_avg:.4f}, '
                          f'Val Loss: {val_loss_avg:.4f}, Train Acc: {train_acc:.4f}, Val Acc: {val_acc:.4f}')
            
            return {
                'train_losses': train_losses,
                'val_losses': val_losses,
                'train_accuracies': train_accuracies,
                'val_accuracies': val_accuracies
            }
        
        def predict(self, X):
            """
            Make predictions
            """
            X_scaled = self.scaler.transform(X)
            X_tensor = torch.FloatTensor(X_scaled)
            
            self.eval()
            with torch.no_grad():
                outputs = self(X_tensor)
                return outputs.numpy()
else:
    class PyTorchSSHDetector:
        """Placeholder class when PyTorch is not available"""
        def __init__(self, *args, **kwargs):
            raise ImportError("PyTorch not available. Install with: pip install torch")

if PYTORCH_AVAILABLE:
    class LSTMSSHDetector(nn.Module):
        """
        LSTM-based model for temporal SSH log analysis
        """
        
        def __init__(self, input_dim, hidden_dim=64, num_layers=2, seq_length=10):
            super(LSTMSSHDetector, self).__init__()
            
            self.hidden_dim = hidden_dim
            self.num_layers = num_layers
            self.seq_length = seq_length
            
            # LSTM layers
            self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, 
                               batch_first=True, dropout=0.2)
            
            # Attention mechanism
            self.attention = nn.MultiheadAttention(hidden_dim, num_heads=8, dropout=0.1)
            
            # Classification layers
            self.classifier = nn.Sequential(
                nn.Linear(hidden_dim, 32),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(32, 1),
                nn.Sigmoid()
            )
            
            self.scaler = StandardScaler()
        
        def forward(self, x):
            # LSTM forward pass
            lstm_out, _ = self.lstm(x)
            
            # Attention mechanism
            attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out)
            
            # Use the last time step for classification
            final_out = attn_out[:, -1, :]
            
            # Classification
            output = self.classifier(final_out)
            
            return output
        
        def prepare_sequences(self, X):
            """
            Prepare sequential data for LSTM
            """
            sequences = []
            for i in range(len(X) - self.seq_length + 1):
                seq = X[i:i+self.seq_length]
                sequences.append(seq)
            
            return np.array(sequences)
else:
    class LSTMSSHDetector:
        """Placeholder class when PyTorch is not available"""
        def __init__(self, *args, **kwargs):
            raise ImportError("PyTorch not available. Install with: pip install torch")

def train_ensemble_models(X, y):
    """
    Train ensemble of different neural network models
    """
    print("Training Ensemble of Neural Network Models...")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    models = {}
    results = {}
    
    # TensorFlow model
    if TENSORFLOW_AVAILABLE:
        print("\n1. Training TensorFlow Model...")
        try:
            tf_model = TensorFlowSSHDetector()
            tf_model.train(X_train, y_train, epochs=30)
            tf_results = tf_model.evaluate(X_test, y_test)
            models['tensorflow'] = tf_model
            results['tensorflow'] = tf_results
        except Exception as e:
            print(f"Failed to train TensorFlow model: {e}")
    else:
        print("\n1. TensorFlow not available, skipping...")
    
    # PyTorch model
    if PYTORCH_AVAILABLE:
        print("\n2. Training PyTorch Model...")
        try:
            pytorch_model = PyTorchSSHDetector(X_train.shape[1])
            pytorch_training = pytorch_model.train_model(X_train, y_train, epochs=50)
            
            # Evaluate PyTorch model
            y_pred_pytorch = pytorch_model.predict(X_test)
            y_pred_pytorch_binary = (y_pred_pytorch > 0.5).astype(int)
            
            pytorch_results = {
                'predictions': y_pred_pytorch_binary,
                'probabilities': y_pred_pytorch
            }
            
            models['pytorch'] = pytorch_model
            results['pytorch'] = pytorch_results
        except Exception as e:
            print(f"Failed to train PyTorch model: {e}")
    else:
        print("\n2. PyTorch not available, skipping...")
    
    if not models:
        print("No neural network frameworks available. Install TensorFlow or PyTorch.")
        return {}, {}
    
    return models, results

if __name__ == "__main__":
    # Generate sample data for testing
    try:
        from sklearn.datasets import make_classification
        
        X, y = make_classification(n_samples=1000, n_features=20, n_redundant=5,
                                 n_informative=15, random_state=42, n_clusters_per_class=1)
        
        # Train ensemble models
        models, results = train_ensemble_models(X, y)
        
        # Display results
        print("\n" + "="*50)
        print("NEURAL NETWORK ENSEMBLE RESULTS")
        print("="*50)
        
        for model_name, result in results.items():
            if 'accuracy' in result:
                print(f"\n{model_name.upper()} Model:")
                print(f"Accuracy: {result['accuracy']:.4f}")
                if 'precision' in result:
                    print(f"Precision: {result['precision']:.4f}")
                if 'recall' in result:
                    print(f"Recall: {result['recall']:.4f}")
    except ImportError as e:
        print(f"Cannot run neural network demo: {e}")
        print("Install required packages: pip install scikit-learn")
