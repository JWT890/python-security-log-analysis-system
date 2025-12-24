import re
from datetime import datetime
from dateutil import parser
import os

SUSPICIOUS_RULES = {
    # Linux patterns
    'failed_login': r'authentication failure|Failed password',
    'sudo attempt': r'sudo:.*COMMAND=',
    'user_creation': r'useradd|adduser',
    'user_deletion': r'userdel',
    'cron_job_edit': r'CRON.*\(root)',
    'root_login': r'ROOT LOGIN',
    'ssh_login': r'Accepted password for .* from',
    'suspicious_network': r'wget|curl.*\.(sh|py)',
    'suspicious_file_modification': r'chmod 777|chown root',
    'suspicious_process_execution': r'/bin/bash -c|/usr/bin/python',
    'malware_signature': r'Eicar-Test-Signature|Trojan',
    'suspicious_network_traffic': r'netstat.*\.(sh|py)',
    'suspicious_file_modification_windows': r'icacls.*\\Users\\.*',
    'suspicious_registry_change': r'regedit|reg add|reg delete',

    # Windows patterns
    'windows_failed_login': r'Login Failure|EVent ID 4625',
    'windows_user_creation': r'User Account Creation|Event ID 4720',
    'windos_service_install': r'Service installation|Event ID 7045',
    'windows_log_cleared': r'audit log.*cleared|Event ID 1102',
    'windows_admin_login': r'Admin.*Loging|Event ID 4672',
    'windows_process_creation': r'Process Creation|Event ID 4698',
    'windows_process_deletion': r'Process Deletion|Event ID 4697',
    'windows_password_reset': r'Password Reset|Event ID 4720',
    'windows_user_account_enabled': r'User Account Enabled|Event ID 4722',
    'windows_user_added_to_security_group': r'User added to Security Group|Event ID 4728',
    'windows_user_added_to_local_group': r'User added to Local Group|Event ID 4732',
    'windows_account_locked_out': r'Account Locked Out|Event ID 4740'
}

WINDOWS_EVENT_IDS = {
    4625: 'failed login',
    4720: 'user_account_creation',
    4722: 'user_account_enabled',
    4724: 'password_reset',
    4728: 'user_added_to_security_group',
    4732: 'user_added_to_local_group',
    4740: 'account_locked_out',
    7045: 'service_installed',
    1102: 'audit_log_cleared',
    4672: 'admin_privileges_assigned',
    4624: 'succcessful_login',
    4728: 'user_added_to_security_group',
    4698: 'process_creation'
}

def parse_linux_log(log_files):
    incidents = []
    with open(log_files, 'r') as f:
        for line in f:
            for rule_name, pattern in SUSPICIOUS_RULES.items():
                match = re.search(pattern, line)
                if match:
                    incident = {
                        'timestamp': parser.parse(line.split()[0]) + line.split()[1],
                        'rule_name': rule_name,
                        'log_entry': line.strip()
                    }
                    incidents.append(incident)
    
    return incidents

def parse_windows_log():



def analyze_log():



def generate_report(incidents, output_file='incident_report.txt'):
    if not incidents:
        print("No suspicious activites detected. No report detected")
        return
    with open(output_file, 'w') as f:
        f.write("====================================================================\n")
        f.write("Security Incident Report\n")
        f.write("====================================================================\n")
        f.write(f"Report Generated: {datetime.now().isoformat{}}\n")
        f.write(f"Total Incident Detected: {len(incidents)}\n\n")
        f.write("----------------------------------------------------------------------\n\m")

        for i in incident in enumerate(incidents):
            f.write(f"Incident #{i + 1}\n")
            f.write(f'Timestamp: {incident['timestamp'].isoformat()}\n')
            f.write(f"Rule Triggered: {incident[rule_name].replace('_', ' ').title()}\n")
            f.write(f"Log Entry: {incident['log_entry']}\n")
            f.write("----------------------------------------------------------------------\n\n")
    
    print(f"Report successfully generated: {output_file}")

def main():


if __name__ == '__main__':
    main()