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



def generate_report(output_file='incident_report.txt'):


def main():


if __name__ == '__main__':
    main()