#!/usr/bin/env python3
"""
Automated response system for SSH bruteforce attacks
Implements various response mechanisms including IP blocking, rate limiting, and alerting
"""

import subprocess
import json
import smtplib
import time
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
import threading
import sqlite3
import ipaddress
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatResponse:
    """
    Automated threat response system for SSH bruteforce attacks
    """
    
    def __init__(self, config_file='response_config.json'):
        self.config = self.load_config(config_file)
        self.blocked_ips = set()
        self.rate_limited_ips = defaultdict(list)
        self.threat_history = defaultdict(list)
        
        # Initialize database
        self.init_database()
        
        # Response thresholds
        self.thresholds = {
            'block_threshold': 0.8,      # Block if threat probability > 80%
            'rate_limit_threshold': 0.6,  # Rate limit if probability > 60%
            'alert_threshold': 0.5,       # Send alert if probability > 50%
            'max_attempts': 10,           # Max failed attempts before action
            'time_window': 300            # Time window in seconds (5 minutes)
        }
        
    def load_config(self, config_file):
        """
        Load configuration from JSON file
        """
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'recipients': []
            },
            'firewall': {
                'enabled': True,
                'use_iptables': True,
                'use_fail2ban': False
            },
            'logging': {
                'log_file': 'threat_responses.log',
                'log_level': 'INFO'
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except FileNotFoundError:
            logger.info(f"Config file {config_file} not found. Using defaults.")
            # Create default config file
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
        
        return default_config
    
    def init_database(self):
        """
        Initialize SQLite database for threat tracking
        """
        self.db_path = 'threat_responses.db'
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                threat_type TEXT,
                probability REAL,
                response_action TEXT,
                details TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                blocked_at DATETIME,
                reason TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_threat_event(self, source_ip, threat_type, probability, response_action, details=None):
        """
        Log threat event to database
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threat_events 
            (timestamp, source_ip, threat_type, probability, response_action, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (datetime.now(), source_ip, threat_type, probability, response_action, details))
        
        conn.commit()
        conn.close()
    
    def handle_threat(self, alert_data):
        """
        Main threat handling function
        """
        source_ip = alert_data.get('source_ip')
        probability = alert_data.get('probability', 0)
        threat_type = alert_data.get('threat_type', 'ssh_bruteforce')
        
        logger.info(f"Handling threat from {source_ip} with probability {probability:.2%}")
        
        # Determine response action based on threat level
        response_actions = []
        
        if probability >= self.thresholds['block_threshold']:
            if self.block_ip(source_ip, f"High threat probability: {probability:.2%}"):
                response_actions.append('blocked')
        
        elif probability >= self.thresholds['rate_limit_threshold']:
            if self.rate_limit_ip(source_ip):
                response_actions.append('rate_limited')
        
        if probability >= self.thresholds['alert_threshold']:
            self.send_alert(alert_data)
            response_actions.append('alert_sent')
        
        # Log the event
        self.log_threat_event(
            source_ip, threat_type, probability, 
            ','.join(response_actions), json.dumps(alert_data)
        )
        
        return response_actions
    
    def block_ip(self, ip_address, reason="SSH bruteforce attack detected"):
        """
        Block IP address using iptables or other firewall
        """
        if ip_address in self.blocked_ips:
            logger.info(f"IP {ip_address} already blocked")
            return False
        
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            
            if self.config['firewall']['use_iptables']:
                # Add iptables rule to block IP
                cmd = [
                    'sudo', 'iptables', '-A', 'INPUT', 
                    '-s', ip_address, '-j', 'DROP'
                ]
                
                # In a real environment, execute the command
                # subprocess.run(cmd, check=True)
                logger.info(f"SIMULATED: Would execute: {' '.join(cmd)}")
                
            self.blocked_ips.add(ip_address)
            
            # Log to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip_address, blocked_at, reason)
                VALUES (?, ?, ?)
            ''', (ip_address, datetime.now(), reason))
            conn.commit()
            conn.close()
            
            logger.info(f"🚫 IP {ip_address} blocked successfully. Reason: {reason}")
            return True
            
        except ipaddress.AddressValueError:
            logger.error(f"Invalid IP address: {ip_address}")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """
        Unblock IP address
        """
        try:
            if self.config['firewall']['use_iptables']:
                # Remove iptables rule
                cmd = [
                    'sudo', 'iptables', '-D', 'INPUT', 
                    '-s', ip_address, '-j', 'DROP'
                ]
                
                # subprocess.run(cmd, check=True)
                logger.info(f"SIMULATED: Would execute: {' '.join(cmd)}")
            
            self.blocked_ips.discard(ip_address)
            
            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE blocked_ips SET is_active = 0 
                WHERE ip_address = ?
            ''', (ip_address,))
            conn.commit()
            conn.close()
            
            logger.info(f"✅ IP {ip_address} unblocked successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    def rate_limit_ip(self, ip_address, duration=300):
        """
        Apply rate limiting to IP address
        """
        current_time = datetime.now()
        end_time = current_time + timedelta(seconds=duration)
        
        self.rate_limited_ips[ip_address].append({
            'start_time': current_time,
            'end_time': end_time,
            'duration': duration
        })
        
        # In a real system, implement actual rate limiting
        # This could involve configuring nginx, apache, or firewall rules
        logger.info(f"⏳ Rate limiting applied to IP {ip_address} for {duration} seconds")
        
        # Schedule automatic removal
        timer = threading.Timer(duration, self._remove_rate_limit, args=[ip_address])
        timer.start()
        
        return True
    
    def _remove_rate_limit(self, ip_address):
        """
        Remove rate limiting for IP address
        """
        current_time = datetime.now()
        
        # Remove expired rate limits
        active_limits = [
            limit for limit in self.rate_limited_ips[ip_address]
            if limit['end_time'] > current_time
        ]
        
        self.rate_limited_ips[ip_address] = active_limits
        
        if not active_limits:
            del self.rate_limited_ips[ip_address]
            logger.info(f"✅ Rate limiting removed for IP {ip_address}")
    
    def send_alert(self, alert_data):
        """
        Send email alert for threat detection
        """
        if not self.config['email']['enabled']:
            logger.info(f"📧 ALERT: {alert_data['source_ip']} - SSH Bruteforce (Probability: {alert_data['probability']:.2%})")
            return
        
        try:
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['username']
            msg['To'] = ', '.join(self.config['email']['recipients'])
            msg['Subject'] = f"🚨 SSH Bruteforce Attack Detected - {alert_data['source_ip']}"
            
            # Email body
            body = f"""
            SSH Bruteforce Attack Detected
            
            Time: {alert_data.get('timestamp', datetime.now())}
            Source IP: {alert_data['source_ip']}
            Username: {alert_data.get('username', 'N/A')}
            Threat Probability: {alert_data['probability']:.2%}
            Total Attempts: {alert_data.get('total_attempts', 'N/A')}
            
            Automated Response Actions:
            - Alert sent to security team
            - IP monitoring increased
            - Consider manual investigation
            
            This is an automated alert from the SSH Bruteforce Detection System.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.config['email']['smtp_server'], self.config['email']['smtp_port'])
            server.starttls()
            server.login(self.config['email']['username'], self.config['email']['password'])
            text = msg.as_string()
            server.sendmail(self.config['email']['username'], self.config['email']['recipients'], text)
            server.quit()
            
            logger.info(f"📧 Alert email sent for threat from {alert_data['source_ip']}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def get_blocked_ips(self):
        """
        Get list of currently blocked IPs
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT ip_address, blocked_at, reason FROM blocked_ips WHERE is_active = 1')
        results = cursor.fetchall()
        conn.close()
        
        return [{'ip': row[0], 'blocked_at': row[1], 'reason': row[2]} for row in results]
    
    def get_threat_statistics(self, hours=24):
        """
        Get threat statistics for the last N hours
        """
        since = datetime.now() - timedelta(hours=hours)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total threats
        cursor.execute('SELECT COUNT(*) FROM threat_events WHERE timestamp > ?', (since,))
        total_threats = cursor.fetchone()[0]
        
        # Threats by IP
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count, AVG(probability) as avg_prob
            FROM threat_events 
            WHERE timestamp > ?
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''', (since,))
        top_threats = cursor.fetchall()
        
        # Response actions
        cursor.execute('''
            SELECT response_action, COUNT(*) as count
            FROM threat_events 
            WHERE timestamp > ?
            GROUP BY response_action
        ''', (since,))
        response_stats = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_threats': total_threats,
            'top_threat_ips': [{'ip': row[0], 'count': row[1], 'avg_probability': row[2]} for row in top_threats],
            'response_actions': dict(response_stats),
            'currently_blocked': len(self.get_blocked_ips()),
            'rate_limited': len(self.rate_limited_ips)
        }
    
    def cleanup_old_blocks(self, days=7):
        """
        Clean up old blocked IPs
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get old blocks
        cursor.execute('SELECT ip_address FROM blocked_ips WHERE blocked_at < ? AND is_active = 1', (cutoff_date,))
        old_blocks = cursor.fetchall()
        
        # Unblock old IPs
        for (ip,) in old_blocks:
            self.unblock_ip(ip)
        
        conn.close()
        
        logger.info(f"Cleaned up {len(old_blocks)} old IP blocks")

class ThreatResponseManager:
    """
    Manager class for coordinating threat responses
    """
    
    def __init__(self):
        self.response_system = ThreatResponse()
        self.active_threats = {}
        self.response_queue = []
        
    def process_threat_alert(self, alert_data):
        """
        Process incoming threat alert
        """
        source_ip = alert_data.get('source_ip')
        
        # Track threat progression
        if source_ip not in self.active_threats:
            self.active_threats[source_ip] = {
                'first_seen': datetime.now(),
                'threat_count': 0,
                'max_probability': 0,
                'responses': []
            }
        
        threat_info = self.active_threats[source_ip]
        threat_info['threat_count'] += 1
        threat_info['last_seen'] = datetime.now()
        threat_info['max_probability'] = max(threat_info['max_probability'], alert_data.get('probability', 0))
        
        # Execute response
        response_actions = self.response_system.handle_threat(alert_data)
        threat_info['responses'].extend(response_actions)
        
        return response_actions
    
    def get_dashboard_data(self):
        """
        Get data for security dashboard
        """
        stats = self.response_system.get_threat_statistics()
        blocked_ips = self.response_system.get_blocked_ips()
        
        dashboard_data = {
            'statistics': stats,
            'blocked_ips': blocked_ips,
            'active_threats': len(self.active_threats),
            'system_status': 'active',
            'last_updated': datetime.now().isoformat()
        }
        
        return dashboard_data

def create_sample_config():
    """
    Create sample configuration file
    """
    config = {
        "email": {
            "enabled": False,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "username": "security@example.com",
            "password": "your_app_password",
            "recipients": ["admin@example.com", "security-team@example.com"]
        },
        "firewall": {
            "enabled": True,
            "use_iptables": True,
            "use_fail2ban": False
        },
        "thresholds": {
            "block_threshold": 0.8,
            "rate_limit_threshold": 0.6,
            "alert_threshold": 0.5,
            "max_attempts": 10,
            "time_window": 300
        },
        "logging": {
            "log_file": "threat_responses.log",
            "log_level": "INFO"
        }
    }
    
    with open('response_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("Sample configuration created: response_config.json")

if __name__ == "__main__":
    # Create sample configuration
    create_sample_config()
    
    # Initialize response system
    response_manager = ThreatResponseManager()
    
    # Simulate threat alerts
    sample_alerts = [
        {
            'source_ip': '203.0.113.50',
            'probability': 0.85,
            'threat_type': 'ssh_bruteforce',
            'username': 'admin',
            'total_attempts': 15,
            'timestamp': datetime.now()
        },
        {
            'source_ip': '198.51.100.25',
            'probability': 0.65,
            'threat_type': 'ssh_bruteforce',
            'username': 'root',
            'total_attempts': 8,
            'timestamp': datetime.now()
        }
    ]
    
    print("🔒 SSH Bruteforce Response System Demo")
    print("=" * 50)
    
    for alert in sample_alerts:
        print(f"\n📊 Processing threat alert from {alert['source_ip']}")
        actions = response_manager.process_threat_alert(alert)
        print(f"🔧 Response actions taken: {', '.join(actions)}")
    
    # Display dashboard data
    print("\n📈 Security Dashboard Data:")
    dashboard = response_manager.get_dashboard_data()
    print(f"Active threats: {dashboard['active_threats']}")
    print(f"Blocked IPs: {len(dashboard['blocked_ips'])}")
    print(f"Total threats (24h): {dashboard['statistics']['total_threats']}")
    
    # Show blocked IPs
    print("\n🚫 Currently Blocked IPs:")
    for blocked in dashboard['blocked_ips']:
        print(f"  {blocked['ip']} - {blocked['reason']}")
