import time
import threading
import queue
import json
from datetime import datetime
import pandas as pd
from ssh_detector import SSHBruteforceDetector

class RealTimeSSHMonitor:
    """
    Real-time SSH log monitoring and threat detection system
    """
    
    def __init__(self, model_path='ssh_bruteforce_models.pkl'):
        self.detector = SSHBruteforceDetector()
        self.detector.load_models(model_path)
        self.log_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.running = False
        self.blocked_ips = set()
        self.threat_scores = {}
        
    def start_monitoring(self):
        """
        Start real-time monitoring threads
        """
        self.running = True
        
        # Start log processing thread
        processing_thread = threading.Thread(target=self._process_logs, daemon=True)
        processing_thread.start()
        
        # Start response thread
        response_thread = threading.Thread(target=self._handle_responses, daemon=True)
        response_thread.start()
        
        print("🔍 SSH Bruteforce Detection System Started")
        print("📡 Monitoring SSH logs in real-time...")
        print("-" * 50)
    
    def add_log_entry(self, log_entry):
        """
        Add a new SSH log entry for processing
        """
        log_entry['timestamp'] = datetime.now()
        self.log_queue.put(log_entry)
    
    def _process_logs(self):
        """
        Process logs from the queue and detect threats
        """
        while self.running:
            try:
                if not self.log_queue.empty():
                    log_entry = self.log_queue.get(timeout=1)
                    self._analyze_log_entry(log_entry)
                else:
                    time.sleep(0.1)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error processing log: {e}")
    
    def _analyze_log_entry(self, log_entry):
        """
        Analyze individual log entry for threats
        """
        try:
            # Predict using the trained model
            result = self.detector.predict_realtime(log_entry)
            
            # Update threat scores
            source_ip = log_entry.get('source_ip', 'unknown')
            if source_ip not in self.threat_scores:
                self.threat_scores[source_ip] = {'score': 0, 'attempts': 0, 'last_seen': datetime.now()}
            
            self.threat_scores[source_ip]['attempts'] += 1
            self.threat_scores[source_ip]['last_seen'] = datetime.now()
            
            if result['is_bruteforce']:
                self.threat_scores[source_ip]['score'] += result['bruteforce_probability']
                
                # Create alert
                alert = {
                    'timestamp': datetime.now(),
                    'severity': 'HIGH' if result['bruteforce_probability'] > 0.8 else 'MEDIUM',
                    'source_ip': source_ip,
                    'username': log_entry.get('username', 'unknown'),
                    'event_type': log_entry.get('event_type', 'unknown'),
                    'probability': result['bruteforce_probability'],
                    'total_attempts': self.threat_scores[source_ip]['attempts'],
                    'cumulative_score': self.threat_scores[source_ip]['score']
                }
                
                self.alert_queue.put(alert)
                
                # Print real-time alert
                self._print_alert(alert)
                
        except Exception as e:
            print(f"Error analyzing log entry: {e}")
    
    def _print_alert(self, alert):
        """
        Print formatted security alert
        """
        severity_color = {
            'HIGH': '\033[91m',    # Red
            'MEDIUM': '\033[93m',  # Yellow
            'LOW': '\033[92m'      # Green
        }
        reset_color = '\033[0m'
        
        color = severity_color.get(alert['severity'], '')
        
        print(f"\n{color}🚨 SECURITY ALERT - {alert['severity']} SEVERITY{reset_color}")
        print(f"⏰ Time: {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🎯 Attack Type: SSH Bruteforce")
        print(f"🌐 Source IP: {alert['source_ip']}")
        print(f"👤 Username: {alert['username']}")
        print(f"📊 Threat Probability: {alert['probability']:.2%}")
        print(f"🔢 Total Attempts: {alert['total_attempts']}")
        print(f"⚠️  Cumulative Score: {alert['cumulative_score']:.2f}")
        print("-" * 50)
    
    def _handle_responses(self):
        """
        Handle automated threat responses
        """
        while self.running:
            try:
                if not self.alert_queue.empty():
                    alert = self.alert_queue.get(timeout=1)
                    self._automated_response(alert)
                else:
                    time.sleep(0.1)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error handling response: {e}")
    
    def _automated_response(self, alert):
        """
        Execute automated response to threats
        """
        source_ip = alert['source_ip']
        
        # Block IP if threat score is high
        if alert['probability'] > 0.7 and source_ip not in self.blocked_ips:
            self.blocked_ips.add(source_ip)
            print(f"🚫 AUTOMATED RESPONSE: IP {source_ip} has been blocked")
            
            # In a real system, this would interface with firewall/iptables
            # Example: subprocess.run(['iptables', '-A', 'INPUT', '-s', source_ip, '-j', 'DROP'])
        
        # Rate limiting for repeated attempts
        if alert['total_attempts'] > 10:
            print(f"⏳ RATE LIMITING: Applied to IP {source_ip}")
    
    def get_threat_summary(self):
        """
        Get summary of current threats
        """
        summary = {
            'total_ips_monitored': len(self.threat_scores),
            'blocked_ips': len(self.blocked_ips),
            'high_risk_ips': len([ip for ip, data in self.threat_scores.items() 
                                if data['score'] > 2.0]),
            'top_threats': sorted(self.threat_scores.items(), 
                                key=lambda x: x[1]['score'], reverse=True)[:5]
        }
        return summary
    
    def stop_monitoring(self):
        """
        Stop the monitoring system
        """
        self.running = False
        print("🛑 SSH Monitoring System Stopped")

def simulate_ssh_traffic():
    """
    Simulate SSH traffic for demonstration
    """
    import random
    import time
    
    # Normal user activities
    normal_users = ['alice', 'bob', 'charlie', 'dave']
    normal_ips = ['192.168.1.10', '192.168.1.20', '192.168.1.30']
    
    # Attacker patterns
    attack_ips = ['10.0.0.100', '203.0.113.50', '198.51.100.25']
    attack_usernames = ['admin', 'root', 'user', 'test', 'guest']
    
    logs = []
    
    # Generate normal traffic
    for _ in range(20):
        logs.append({
            'source_ip': random.choice(normal_ips),
            'username': random.choice(normal_users),
            'event_type': random.choice(['successful_login', 'failed_login']),
            'port': 22
        })
    
    # Generate attack traffic
    for attack_ip in attack_ips:
        for _ in range(15):  # Multiple attempts from same IP
            logs.append({
                'source_ip': attack_ip,
                'username': random.choice(attack_usernames),
                'event_type': 'failed_login',
                'port': 22
            })
    
    return logs

if __name__ == "__main__":
    # Initialize and start monitoring
    monitor = RealTimeSSHMonitor()
    
    try:
        monitor.start_monitoring()
        
        # Simulate SSH traffic
        simulated_logs = simulate_ssh_traffic()
        
        print("🔄 Simulating SSH traffic...")
        for log in simulated_logs:
            monitor.add_log_entry(log)
            time.sleep(0.5)  # Simulate real-time delays
        
        # Wait for processing
        time.sleep(5)
        
        # Print threat summary
        print("\n" + "="*50)
        print("THREAT DETECTION SUMMARY")
        print("="*50)
        
        summary = monitor.get_threat_summary()
        print(f"📊 Total IPs Monitored: {summary['total_ips_monitored']}")
        print(f"🚫 Blocked IPs: {summary['blocked_ips']}")
        print(f"⚠️  High Risk IPs: {summary['high_risk_ips']}")
        
        print("\n🔝 Top Threat IPs:")
        for ip, data in summary['top_threats']:
            if data['score'] > 0:
                print(f"   {ip}: Score {data['score']:.2f}, Attempts {data['attempts']}")
        
    except KeyboardInterrupt:
        print("\n⏹️  Stopping monitoring...")
    finally:
        monitor.stop_monitoring()
