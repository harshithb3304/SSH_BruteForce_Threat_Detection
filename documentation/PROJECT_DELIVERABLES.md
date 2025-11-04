# Project Deliverables Document

**Project Title:** AI-Based Real-Time Threat Analysis for Networks  
**Selected Attack Type:** SSH Bruteforce Attacks  
**Student Name:** Harshith B  
**Date:** October 16, 2025  

---

## 0. Attack Description & Behavior

### 0.1 SSH Bruteforce Attack Overview
SSH Bruteforce attacks are automated attempts to gain unauthorized access to systems by systematically trying various username/password combinations against SSH (Secure Shell) services.

### 0.2 Attack Characteristics
- **Automated Attack Patterns**: Systematic, programmatic attempts to gain unauthorized access
- **High Frequency Attempts**: Multiple login attempts within short time windows (typically >5 attempts/minute)
- **Administrative Account Targeting**: Focus on privileged accounts (root, admin, user, test)
- **Dictionary-Based Attacks**: Use of common username/password combinations from dictionaries
- **Distributed Sources**: Attacks often originate from multiple IP addresses to evade simple rate limiting
- **Rapid Successive Failed Logins**: Multiple failed authentication attempts from the same source IP

### 0.3 Attack Behavior Patterns
**Temporal Patterns:**
- Attacks show clustering during specific hours (off-peak hours common)
- High-frequency bursts indicate automated attack patterns

**Authentication Patterns:**
- Systematic enumeration of common usernames (admin, root, user, test, guest)
- Dictionary-based password attacks using common passwords
- Invalid user attempts followed by password attempts
- Connection attempts without proper authentication

**System-Level Indicators:**
- High frequency of connection attempts (connect events)
- Failed operations indicated by error codes (returnValue: -1, -13)
- SSH daemon (sshd) processes heavily involved
- Root user (userId=0) shows higher attack correlation

### 0.4 Threat Impact
- **Prevalence**: 80%+ of SSH services experience bruteforce attempts
- **Success Rate**: 2-5% success rate against weak credential systems
- **Economic Impact**: Average $4.35M per successful data breach (IBM Security Report 2023)
- **Detection Challenge**: Distinguishing legitimate failed logins from malicious attempts

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
- ☑️ Isolation Forest
- ☑️ Logistic Regression
- ☐ LSTM
- ☐ CNN
- ☐ Autoencoder
- ☑️ Hybrid/Ensemble
- ☐ Other: ___________

**Supervised Model: Logistic Regression**
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
- **Logistic Regression** trained on labeled BETH data (is_attack labels)
- Learns patterns from known SSH attack signatures (1,269 attacks in training)
- Achieves 94.56% accuracy on independent test set
- Provides interpretable coefficients for feature analysis

**Unsupervised Component:**
- **Isolation Forest** learns normal behavior from training data (NO labels used)
- Trained on 761,875 normal samples to learn normality
- Flags deviations as anomalies (attack = 1, normal = 0)
- Achieves 92.44% accuracy on independent test set
- Why chosen: Fast, handles high-dimensional data, ideal for real-time monitoring

**Ensemble Strategy:**
- Both models vote: If both agree → use that prediction
- If they disagree → trust supervised (more reliable for known patterns)
- Final performance: 94.56% accuracy, 99.95% precision, 94.05% recall

---

## 5. Model Training & Evaluation

### 5.1 Supervised Learning (Labeled Data)

**Evaluation Metrics (Independent Test Set):**

| Metric | Logistic Regression (Supervised) | Isolation Forest (Unsupervised) | Ensemble (LR + IF) |
|--------|----------------------------------|----------------------------------|---------------------|
| **Accuracy** | **94.56%** | **92.44%** | **94.56%** |
| **Precision** | **99.95%** | **N/A** | **99.95%** |
| **Recall** | **94.05%** | **N/A** | **94.05%** |
| **F1 Score** | **96.95%** | **N/A** | **96.95%** |
| **AUC-ROC** | **98.12%** | **N/A** | **97.66%** |

**Note:** Isolation Forest is **unsupervised** (no labels used during training). It learns normal behavior patterns and flags anomalies, but doesn't optimize for precision/recall/F1. These metrics are calculated post-hoc for evaluation only - IF itself doesn't use them during training or prediction.

**Cross-Validation Results:**
- **Mean Accuracy:** 99.98% ± 0.0000
- **95% Confidence Interval:** [99.98%, 99.98%]
- **Stability:** Extremely consistent across folds

**Confusion Matrix (Ensemble):**
```
                Predicted
                Normal    Attack
Actual Normal  [[17,424    84]]
       Attack  [[10,195  161,264]]

Security Metrics:
├── Detection Rate: 94.05% (161,264/171,459)
├── False Alarm Rate: 0.48% (84/17,508)
├── True Positive Rate: 94.05%
└── False Positive Rate: 0.48%
```

### 5.2 Unsupervised Learning Component

**Unsupervised Model: Isolation Forest**
- **Method:** Tree-based anomaly detection that isolates outliers by random splits
- **Training:** Learns normal behavior from 761,875 normal samples (no labels used)
- **Prediction:** Returns -1 for anomaly (attack) or 1 for normal
- **Why chosen:** Fast (O(n log n)), handles high-dimensional data, no distribution assumptions
- **Performance:** 92.44% accuracy on independent test set

**Comparison with Other Unsupervised Models:**
- **DBSCAN:** Needs tuning, struggles with high dimensions
- **One-Class SVM:** Slower (O(n²)), memory intensive
- **Autoencoder:** Overkill for 13 features, needs GPU
- **LOF:** Slower and memory intensive

**Ensemble Integration:**
- Both models vote independently
- If both agree → high confidence in prediction
- If disagree → trust supervised (more reliable for known attack patterns)

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
- **High Precision (99.95%):** Minimizes false alarms for operational deployment
- **Good Recall (94.05%):** Catches majority of SSH bruteforce attempts  
- **Real-time Capable:** Sub-second response suitable for production environments
- **Robust Performance:** Stable across different validation approaches

**Strengths:**
- Successfully prevented overfitting through proper train/test separation
- Achieved realistic performance metrics on independent datasets
- Demonstrated scalable real-time processing capabilities
- Provided interpretable feature importance for security analysis

**Weaknesses:**
- 5.95% false negative rate means some attacks go undetected (10,195 missed attacks)
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

## 8. Methodology, Results & Conclusions

### 8.1 Training Methodology
**Code Location**: `scripts/proper_training.py`

**Training Process:**
1. **Data Loading**: Load separate train/test files (prevents data leakage)
   - Training: `datasets/labelled_training_data.csv` (763,144 samples)
   - Testing: `datasets/labelled_testing_data.csv` (188,967 samples)

2. **Feature Extraction**: Extract 13 features per sample
   - Temporal features (hour, minute)
   - Process features (processId, parentProcessId, userId)
   - Event features (eventId, argsNum, returnValue)
   - Binary indicators (processName_sshd, processName_systemd, event_*)

3. **Feature Scaling**: Apply StandardScaler normalization

4. **Model Training**:
   - **Logistic Regression (Supervised)**: Trained on labeled data (is_attack)
   - **Isolation Forest (Unsupervised)**: Trained on normal samples only (761,875 samples)

5. **Ensemble**: Both models vote, disagreement resolved by trusting supervised

6. **Model Persistence**: Saved as `models/ensemble.pkl`

### 8.2 Results Summary
**Final Performance (Independent Test Set):**
- **Ensemble Accuracy**: 94.56%
- **Precision**: 99.95% (only 84 false positives out of 17,508 normal events)
- **Recall**: 94.05% (161,264 out of 171,459 attacks detected)
- **F1-Score**: 96.95%
- **ROC-AUC**: 97.66%
- **False Alarm Rate**: 0.48%

**Key Achievements:**
- Successfully prevented overfitting through proper train/test separation
- Achieved realistic performance metrics on independent datasets
- Demonstrated scalable real-time processing capabilities
- Combined supervised (known patterns) + unsupervised (novel anomalies) learning

### 8.3 Conclusions
The hybrid ensemble approach (Logistic Regression + Isolation Forest) successfully detects SSH bruteforce attacks with high precision (99.95%) and good recall (94.05%). The system is production-ready with sub-second response times and minimal false alarms. The unsupervised component (Isolation Forest) provides additional protection against novel attack patterns not seen in training data.

---

## 9. Code & Resources

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
- `scripts/proper_training.py` - Main training pipeline (trains LR + IF ensemble)
- `scripts/simulate_realtime.py` - Real-time detection simulation demo
- `run_simulation.sh` - Demo runner script (quick/extended demo)
- `scripts/comprehensive_testing.py` - Complete evaluation framework
- `scripts/realtime_monitor.py` - Real-time detection system
- `documentation/REPORT.md` - Comprehensive technical report with full methodology
- `documentation/README.md` - Quick start guide and script explanations

**Performance Benchmarks:**
- **Processing Speed:** 82,434 samples/second (batch mode)
- **Single Prediction:** 12.39ms average latency
- **Memory Usage:** <100MB for inference
- **Model Size:** <380KB total for both models

---

*Document Generated: October 16, 2025*  
*Last Updated: October 16, 2025*