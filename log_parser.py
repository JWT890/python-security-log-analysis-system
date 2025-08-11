import re
from datetime import datetime
from dateutil import parser
import os

SUSPICIOUS_RULES = {
    'failed_login': r'authentication failure',
    'sudo_attempt': r'sudo: .* COMMAND=(.*)',
    'user_creation': r'useradd|adduser',
    'cron_job_edit': r'CRON.*(pam_unix|session)',
}

def parse_log():


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