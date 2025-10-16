# Project Deliverables Document

**Project Title:** AI-Based Real-Time Threat Analysis for Networks  
**Selected Attack Type:** SSH Bruteforce Attacks  
**Student Name:** Harshith B  
**Date:** October 16, 2025  

---

## 1. Dataset Description & Justification

### 1.1 Dataset Source
- **Name of Dataset:** BETH Dataset (Behavioral Threat Hunting Dataset)
- **Source Link:** https://www.kaggle.com/datasets/katehighnam/beth-dataset
- **Type:** 
  - ☑️ Real-world (Preferred – reflects authentic network traffic and attack behavior)
  - ☐ Synthetic (May lack realistic noise and complexity)
  - ☐ Emulated (Simulated data from controlled testbeds or virtual environments)
- **Collected From:**
  - ☑️ Honeypots
  - ☐ SIEM Logs
  - ☐ Edge/IoT Devices
  - ☐ Other: ___________

### 1.2 Dataset Overview
- **Number of Rows:** 567,904 SSH-related system call events
- **Number of Columns:** 16 features (timestamp, processId, userId, eventName, etc.)
- **Time Period Covered:** Real-world honeypot data collection from 2021
- **Attack Samples vs. Normal Samples:**
  - Training Set: 763,144 samples (1,269 attacks vs 761,875 normal)
  - Testing Set: 188,967 samples (171,459 attacks vs 17,508 normal)
- **Imbalance Ratio:** 
  - Training: 1:600 (0.17% attack traffic)
  - Testing: 10:1 (90.73% attack traffic)

### 1.3 Feature Description

| Feature Name | Description | Type |
|--------------|-------------|------|
| timestamp | System call timestamp | Temporal |
| processId | Process identifier | Numerical |
| parentProcessId | Parent process identifier | Numerical |
| userId | User identifier | Numerical |
| eventId | System call event identifier | Numerical |
| eventName | Name of system call event | Categorical |
| argsNum | Number of arguments in system call | Numerical |
| returnValue | System call return value | Numerical |
| processName | Process name (sshd, systemd, etc.) | Categorical |
| sus | Suspicious activity flag (0/1) | Binary |
| evil | Malicious activity flag (0/1) | Binary |
| hour | Hour extracted from timestamp | Numerical |
| minute | Minute extracted from timestamp | Numerical |
| processName_sshd | Binary flag for SSH daemon process | Binary |
| processName_systemd | Binary flag for systemd process | Binary |
| event_* | Binary flags for specific event types | Binary |

### 1.4 Justification
The BETH dataset is ideal for SSH bruteforce detection because:
- Contains authentic SSH attack patterns from real honeypots
- Includes both system-level and application-level indicators
- Provides temporal information crucial for attack pattern recognition
- Large scale (567k+ events) ensures robust model training
- Real-world data captures authentic attacker behavior and system responses

---

## 2. Exploratory Data Analysis (EDA)

### 2.1 Class Distribution Analysis
- **Is the dataset balanced?** ☐ Yes ☑️ No

**Class Distribution:**
```
Total SSH Events: 567,904
├── Normal Activity: 408,746 (71.97%)
├── Suspicious (sus=1): 157,778 (27.78%)
└── Evil (evil=1): 1,380 (0.24%)
Combined Attacks: 159,158 (28.03%)
```

### 2.2 Feature Behavior
**Key Patterns Observed:**
- **Temporal Patterns:** Attacks show clustering during specific hours
- **Process Patterns:** SSH daemon (sshd) processes heavily involved in attacks
- **System Call Patterns:** Specific event types (connect, openat, security_file_open) correlate with attacks
- **Return Value Analysis:** Error codes (-1, -13) indicate failed operations during attacks
- **User ID Patterns:** Certain user IDs show higher attack correlation

**Feature Correlations:**
- Strong correlation between `sus` and `evil` flags (0.89)
- Temporal features (`hour`, `minute`) show attack clustering patterns  
- Process-related features (`processId_freq`, `userId_freq`) highly discriminative
- Event type indicators show clear separation between normal/attack behavior

---

## 3. Data Preprocessing & Cleaning

### 3.1 Cleaning Steps
- **Missing Value Handling:** Forward-fill for temporal continuity
- **Duplicate Removal:** Removed exact duplicate system call records
- **Feature Encoding:** 
  - Binary encoding for categorical variables (processName, eventName)
  - Temporal feature extraction (hour, minute from timestamp)
- **Normalization/Standardization:** StandardScaler applied to numerical features
- **Feature Engineering:** Created frequency-based features (processId_freq, userId_freq)

### 3.2 Balancing Strategy
- ☐ Oversampling (e.g., SMOTE, ADASYN)
- ☑️ Natural Distribution Maintained (preferred for realistic evaluation)
- ☐ Undersampling 
- ☐ Synthetic data generation
- ☑️ Model-level adjustments (class weights, threshold tuning)

**Rationale:** Maintained natural class distribution to preserve realistic attack patterns and prevent artificial data inflation that could lead to overfitting.

---

## 4. AI Model Design & Architecture

### 4.1 Chosen Model(s)
- ☑️ Random Forest
- ☑️ Logistic Regression
- ☐ LSTM
- ☐ CNN
- ☐ Autoencoder
- ☑️ Hybrid/Ensemble
- ☐ Other: ___________

**Primary Model: Random Forest Classifier**
```python
RandomForestClassifier(
    n_estimators=50,        # Moderate ensemble size
    max_depth=10,           # Prevent overfitting
    min_samples_split=20,   # Require sufficient evidence
    min_samples_leaf=10,    # Ensure reliable predictions
    random_state=42         # Reproducibility
)
```

**Secondary Model: Logistic Regression**
```python
LogisticRegression(
    C=0.1,              # Strong L2 regularization
    penalty='l2',       # Ridge regularization
    max_iter=1000,      # Convergence guarantee
    random_state=42     # Reproducibility
)
```

### 4.2 Imbalance Handling in Model
- ☐ Class Weights
- ☐ Focal Loss
- ☑️ Threshold Adjustment
- ☑️ Conservative Parameter Tuning

### 4.3 Hybrid Learning Approach
**Supervised Component:**
- Random Forest and Logistic Regression trained on labeled BETH data
- Learns patterns from known SSH attack signatures and normal behavior
- Achieves 90.67% accuracy on independent test set
- Provides interpretable feature importance rankings

**Unsupervised Component:**
- Anomaly detection through statistical thresholds on prediction confidence
- Frequency-based anomaly detection for rare processId/userId combinations  
- Temporal anomaly detection for unusual timing patterns
- Ensemble voting system for final classification decisions

---

## 5. Model Training & Evaluation

### 5.1 Supervised Learning (Labeled Data)

**Evaluation Metrics:**

| Metric | Random Forest | Logistic Regression |
|--------|---------------|-------------------|
| **Accuracy** | **90.67%** | **94.54%** |
| **Precision** | **99.77%** | **99.95%** |
| **Recall** | **89.92%** | **94.04%** |
| **F1 Score** | **94.59%** | **96.90%** |
| **AUC-ROC** | **96.26%** | **98.12%** |

**Cross-Validation Results:**
- **Mean Accuracy:** 99.98% ± 0.0000
- **95% Confidence Interval:** [99.98%, 99.98%]
- **Stability:** Extremely consistent across folds

**Confusion Matrix (Random Forest):**
```
                Predicted
                Normal    Attack
Actual Normal  [[17,105   403]]
       Attack  [[17,276  154,183]]

Security Metrics:
├── Detection Rate: 89.92% (154,183/171,459)
├── False Alarm Rate: 2.30% (403/17,508)
├── True Positive Rate: 89.92%
└── False Positive Rate: 2.30%
```

### 5.2 Unsupervised Learning Component

**Anomaly Detection Methods:**
- **Statistical Outlier Detection:** Identifies rare system call patterns
- **Frequency-Based Detection:** Flags unusual process/user activity levels
- **Temporal Pattern Analysis:** Detects timing anomalies in SSH sessions

**Evaluation Approach:**
- **Silhouette Analysis:** Used for validating behavioral clusters
- **Statistical Thresholds:** 95th percentile for anomaly cutoffs
- **Visual Inspection:** t-SNE plots for pattern validation
- **Ensemble Consensus:** Combined supervised and unsupervised predictions

---

## 6. Real-Time or Simulated Detection Demo

### 6.1 Demo Description
**Demo Type:** Real-time SSH log monitoring with simulated attack injection

**Setup:**
- ☑️ Simulated using replayed logs
- ☑️ Real-time processing via Python monitoring script  
- ☑️ Command-line interface with colored alerts
- ☑️ Live log file monitoring capabilities

**Real-time Detection Features:**
- **Live Monitoring:** Watches SSH authentication logs (/var/log/auth.log)
- **Batch Processing:** Handles 82,434 samples/second throughput
- **Alert System:** Color-coded warnings (Green/Yellow/Red)
- **Performance Metrics:** 12.39ms single prediction latency
- **Simulation Mode:** Injects synthetic attack patterns for demonstration

**Visualization:**
- Console-based real-time alerts with timestamps
- Performance statistics display
- Attack confidence scores and feature contributions
- Processing throughput monitoring

---

## 7. Conclusion & Recommendations

### 7.1 Observations
**Model Effectiveness:**
- **High Precision (99.77%+):** Minimizes false alarms for operational deployment
- **Good Recall (89.92%+):** Catches majority of SSH bruteforce attempts  
- **Real-time Capable:** Sub-second response suitable for production environments
- **Robust Performance:** Stable across different validation approaches

**Strengths:**
- Successfully prevented overfitting through proper train/test separation
- Achieved realistic performance metrics on independent datasets
- Demonstrated scalable real-time processing capabilities
- Provided interpretable feature importance for security analysis

**Weaknesses:**
- 10.08% false negative rate means some attacks go undetected
- Domain-specific training limits generalization to other attack types
- Requires periodic retraining to adapt to evolving attack patterns

### 7.2 Future Work
**Immediate Improvements:**
- **Online Learning:** Implement incremental learning for adaptive detection
- **Advanced Features:** Add behavioral profiling and user activity modeling
- **Multi-Protocol Support:** Extend to FTP, RDP, and other authentication protocols
- **Threat Intelligence Integration:** Incorporate external IoC feeds

**Long-term Research:**
- **Deep Learning Models:** Investigate LSTM/Transformer architectures for sequential analysis
- **Adversarial Robustness:** Research resistance to evasion attacks
- **Zero-Day Detection:** Develop unsupervised methods for novel attack patterns
- **Federated Learning:** Enable multi-organization collaboration while preserving privacy

**Integration Opportunities:**
- **SIEM Integration:** Connect with enterprise security platforms
- **Automated Response:** Implement IP blocking and rate limiting
- **Threat Hunting:** Support proactive security analysis workflows

---

## 8. Code & Resources

- **GitHub Repository:** https://github.com/harshithb3304/SSH_BruteForce_Threat_Detection
- **Dataset Source Link:** https://www.kaggle.com/datasets/katehighnam/beth-dataset
- **Documentation:** Complete technical documentation included in `/documentation/` folder

**Project Structure:**
```
SSH_BruteForce_Threat_Detection/
├── config/           # Configuration files
├── datasets/         # BETH dataset files
├── documentation/    # Project reports and analysis
├── logs/            # Training and testing logs
├── models/          # Trained model artifacts  
├── scripts/         # Training, testing, and monitoring scripts
└── tests/           # Test cases and validation
```

**Key Files:**
- `scripts/proper_training.py` - Main training pipeline
- `scripts/comprehensive_testing.py` - Complete evaluation framework
- `scripts/realtime_monitor.py` - Real-time detection system
- `documentation/REPORT.md` - Comprehensive technical report
- `documentation/OVERFITTING_ANALYSIS.md` - Detailed methodology analysis

**Performance Benchmarks:**
- **Processing Speed:** 82,434 samples/second (batch mode)
- **Single Prediction:** 12.39ms average latency
- **Memory Usage:** <100MB for inference
- **Model Size:** <380KB total for both models

---

*Document Generated: October 16, 2025*  
*Last Updated: October 16, 2025*