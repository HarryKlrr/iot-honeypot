#!/usr/bin/env python3
"""
Enhanced Attack Pattern Analyzer for Lightweight IoT Honeypot Project
Analyzes SSH brute-force attempts and Web attacks from logs

Usage: python3 enhanced_credential_analyzer.py
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from collections import Counter
import numpy as np
import re

# Configuration
plt.style.use('default')
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10
plt.rcParams['axes.grid'] = True
plt.rcParams['grid.alpha'] = 0.3


def load_cowrie_data(filename):
    """Load and parse Cowrie JSON log file"""
    entries = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        entry = json.loads(line)
                        entries.append(entry)
                    except json.JSONDecodeError:
                        continue
        print(f"Loaded {len(entries)} log entries from {filename}")
        return entries
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        return []


def load_web_data(filename):
    """Load and parse web attack logs"""
    attacks = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                if line.strip():
                    # Parse log format: IP - - [timestamp] "method path protocol" status -
                    match = re.match(r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) -', line)
                    if match:
                        ip, timestamp_str, method, path, protocol, status = match.groups()
                        try:
                            timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y %H:%M:%S')
                            attacks.append({
                                'timestamp': timestamp,
                                'ip': ip,
                                'method': method,
                                'path': path,
                                'protocol': protocol,
                                'status': int(status)
                            })
                        except:
                            continue
        print(f"Loaded {len(attacks)} web attacks from {filename}")
        return attacks
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        return []


def extract_login_attempts(entries):
    """Extract login attempt data from Cowrie logs"""
    attempts = []

    for entry in entries:
        if entry.get('eventid') == 'cowrie.login.success':
            attempts.append({
                'timestamp': datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00')),
                'username': entry.get('username', ''),
                'password': entry.get('password', ''),
                'success': True,
                'src_ip': entry.get('src_ip', ''),
                'session': entry.get('session', '')
            })
        elif entry.get('eventid') == 'cowrie.login.failed':
            attempts.append({
                'timestamp': datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00')),
                'username': entry.get('username', ''),
                'password': entry.get('password', ''),
                'success': False,
                'src_ip': entry.get('src_ip', ''),
                'session': entry.get('session', '')
            })

    return pd.DataFrame(attempts)


def identify_web_tool(path):
    """Identify attack tool based on path patterns"""
    path_lower = path.lower()

    # Nikto signatures
    nikto_patterns = ['/server-status', '/server-info', '/icons/', '/cgi-bin/',
                      '/admin/', '/config/', '/test/', '/phpmyadmin/', '/mysql/']

    # Dirb/directory enumeration signatures
    dirb_patterns = ['/docs/', '/images/', '/css/', '/js/', '/backup/',
                     '/tmp/', '/uploads/', '/download/', '/data/']

    # Check for Nikto patterns
    for pattern in nikto_patterns:
        if pattern in path_lower:
            return 'Nikto'

    # Check for Dirb patterns
    for pattern in dirb_patterns:
        if pattern in path_lower:
            return 'Dirb'

    # Default classification
    if path.startswith('/cgi') or 'admin' in path_lower or 'config' in path_lower:
        return 'Nikto'
    elif path.count('/') > 2 or path.endswith('.asp') or path.endswith('.aspx'):
        return 'Dirb'
    else:
        return 'Generic'


def analyze_credentials(df, run_name):
    """Generate credential analysis and visualizations"""
    if df.empty:
        print(f"No login attempts found in {run_name}")
        return

    print(f"\n=== {run_name} SSH Analysis ===")
    print(f"Total login attempts: {len(df)}")
    print(f"Successful logins: {df['success'].sum()}")
    print(f"Failed logins: {(~df['success']).sum()}")
    print(f"Unique usernames: {df['username'].nunique()}")
    print(f"Unique passwords: {df['password'].nunique()}")
    print(f"Unique source IPs: {df['src_ip'].nunique()}")

    # Create subplot figure
    fig = plt.figure(figsize=(16, 12))
    fig.suptitle(f'SSH Brute-Force Analysis - {run_name}', fontsize=16, fontweight='bold')

    # 1. Top 10 Usernames
    ax1 = plt.subplot(2, 3, 1)
    top_users = df['username'].value_counts().head(10)
    bars1 = ax1.bar(range(len(top_users)), top_users.values, color='steelblue', alpha=0.7)
    ax1.set_xlabel('Username')
    ax1.set_ylabel('Attempt Count')
    ax1.set_title('Top 10 Most Attempted Usernames')
    ax1.set_xticks(range(len(top_users)))
    ax1.set_xticklabels(top_users.index, rotation=45, ha='right')

    # Add value labels on bars
    for i, bar in enumerate(bars1):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width() / 2., height + 0.5,
                 f'{int(height)}', ha='center', va='bottom', fontsize=8)

    # 2. Top 10 Passwords
    ax2 = plt.subplot(2, 3, 2)
    top_passwords = df['password'].value_counts().head(10)
    bars2 = ax2.bar(range(len(top_passwords)), top_passwords.values, color='darkred', alpha=0.7)
    ax2.set_xlabel('Password')
    ax2.set_ylabel('Attempt Count')
    ax2.set_title('Top 10 Most Attempted Passwords')
    ax2.set_xticks(range(len(top_passwords)))
    ax2.set_xticklabels(top_passwords.index, rotation=45, ha='right')

    # Add value labels on bars
    for i, bar in enumerate(bars2):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width() / 2., height + 0.5,
                 f'{int(height)}', ha='center', va='bottom', fontsize=8)

    # 3. Success vs Failure Rate
    ax3 = plt.subplot(2, 3, 3)
    success_counts = df['success'].value_counts()
    labels = ['Failed', 'Successful'] if False in success_counts else ['Successful']
    values = [success_counts.get(False, 0), success_counts.get(True, 0)]
    colors = ['lightcoral', 'lightgreen']

    wedges, texts, autotexts = ax3.pie(values, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax3.set_title('Login Success vs Failure Rate')

    # 4. Attack Timeline
    ax4 = plt.subplot(2, 3, 4)
    # Group by minute for timeline
    df['timestamp_rounded'] = df['timestamp'].dt.round('1min')
    timeline = df.groupby('timestamp_rounded').size()

    ax4.plot(timeline.index, timeline.values, marker='o', linewidth=2, markersize=4, color='purple', alpha=0.7)
    ax4.set_xlabel('Time')
    ax4.set_ylabel('Attempts per Minute')
    ax4.set_title('Attack Timeline (Attempts Over Time)')
    ax4.tick_params(axis='x', rotation=45)

    # Format x-axis for better readability
    if len(timeline) > 10:
        ax4.xaxis.set_major_locator(mdates.MinuteLocator(interval=max(1, len(timeline) // 10)))
    ax4.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

    # 5. Source IP Distribution
    ax5 = plt.subplot(2, 3, 5)
    ip_counts = df['src_ip'].value_counts().head(5)
    bars5 = ax5.bar(range(len(ip_counts)), ip_counts.values, color='orange', alpha=0.7)
    ax5.set_xlabel('Source IP')
    ax5.set_ylabel('Attempt Count')
    ax5.set_title('Top 5 Source IPs')
    ax5.set_xticks(range(len(ip_counts)))
    ax5.set_xticklabels(ip_counts.index, rotation=45, ha='right')

    # Add value labels
    for i, bar in enumerate(bars5):
        height = bar.get_height()
        ax5.text(bar.get_x() + bar.get_width() / 2., height + 0.5,
                 f'{int(height)}', ha='center', va='bottom', fontsize=8)

    # 6. Session Duration Analysis (if available)
    ax6 = plt.subplot(2, 3, 6)
    sessions = df['session'].value_counts()
    ax6.hist(sessions.values, bins=20, color='teal', alpha=0.7, edgecolor='black')
    ax6.set_xlabel('Attempts per Session')
    ax6.set_ylabel('Number of Sessions')
    ax6.set_title('Session Attempt Distribution')

    plt.tight_layout()

    # Save the plot
    filename = f'credential_analysis_{run_name.lower().replace(" ", "_")}.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    print(f"Saved visualization: {filename}")

    plt.show()

    return {
        'total_attempts': len(df),
        'successful_logins': df['success'].sum(),
        'failed_logins': (~df['success']).sum(),
        'unique_users': df['username'].nunique(),
        'unique_passwords': df['password'].nunique(),
        'top_usernames': top_users.to_dict(),
        'top_passwords': top_passwords.to_dict(),
        'timeline': timeline
    }


def analyze_web_attacks(attacks_list, run_name):
    """Generate web attack analysis and visualizations"""
    if not attacks_list:
        print(f"No web attacks found in {run_name}")
        return

    df = pd.DataFrame(attacks_list)
    df['tool'] = df['path'].apply(identify_web_tool)

    print(f"\n=== {run_name} Web Analysis ===")
    print(f"Total HTTP requests: {len(df)}")
    print(f"Unique paths: {df['path'].nunique()}")
    print(f"404 errors: {(df['status'] == 404).sum()}")
    print(f"200 responses: {(df['status'] == 200).sum()}")

    # Create subplot figure
    fig = plt.figure(figsize=(16, 12))
    fig.suptitle(f'Web Attack Analysis - {run_name}', fontsize=16, fontweight='bold')

    # 1. Top 10 Requested Paths
    ax1 = plt.subplot(2, 3, 1)
    top_paths = df['path'].value_counts().head(10)
    bars1 = ax1.barh(range(len(top_paths)), top_paths.values, color='steelblue', alpha=0.7)
    ax1.set_ylabel('Path')
    ax1.set_xlabel('Request Count')
    ax1.set_title('Top 10 Most Requested Paths')
    ax1.set_yticks(range(len(top_paths)))
    # Truncate long paths for display
    truncated_paths = [path[:30] + '...' if len(path) > 30 else path for path in top_paths.index]
    ax1.set_yticklabels(truncated_paths)
    ax1.invert_yaxis()

    # Add value labels
    for i, bar in enumerate(bars1):
        width = bar.get_width()
        ax1.text(width + 0.5, bar.get_y() + bar.get_height() / 2.,
                 f'{int(width)}', ha='left', va='center', fontsize=8)

    # 2. HTTP Status Code Distribution
    ax2 = plt.subplot(2, 3, 2)
    status_counts = df['status'].value_counts()
    colors = ['lightcoral' if x == 404 else 'lightgreen' if x == 200 else 'gold' for x in status_counts.index]
    bars2 = ax2.bar(range(len(status_counts)), status_counts.values, color=colors, alpha=0.7)
    ax2.set_xlabel('Status Code')
    ax2.set_ylabel('Count')
    ax2.set_title('HTTP Status Code Distribution')
    ax2.set_xticks(range(len(status_counts)))
    ax2.set_xticklabels(status_counts.index)

    # Add value labels
    for i, bar in enumerate(bars2):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width() / 2., height + max(status_counts.values) * 0.01,
                 f'{int(height)}', ha='center', va='bottom', fontsize=8)

    # 3. Attack Tool Distribution
    ax3 = plt.subplot(2, 3, 3)
    tool_counts = df['tool'].value_counts()
    colors = ['steelblue', 'darkred', 'purple'][:len(tool_counts)]
    wedges, texts, autotexts = ax3.pie(tool_counts.values, labels=tool_counts.index,
                                       colors=colors, autopct='%1.1f%%', startangle=90)
    ax3.set_title('Attack Tool Distribution')

    # 4. Request Timeline
    ax4 = plt.subplot(2, 3, 4)
    df['timestamp_rounded'] = df['timestamp'].dt.round('1min')
    timeline = df.groupby('timestamp_rounded').size()

    ax4.plot(timeline.index, timeline.values, marker='o', linewidth=2, markersize=4, color='darkred', alpha=0.7)
    ax4.set_xlabel('Time')
    ax4.set_ylabel('Requests per Minute')
    ax4.set_title('Web Attack Timeline')
    ax4.tick_params(axis='x', rotation=45)

    # Format x-axis
    if len(timeline) > 10:
        ax4.xaxis.set_major_locator(mdates.MinuteLocator(interval=max(1, len(timeline) // 10)))
    ax4.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

    # 5. Request Methods Distribution
    ax5 = plt.subplot(2, 3, 5)
    method_counts = df['method'].value_counts()
    bars5 = ax5.bar(range(len(method_counts)), method_counts.values, color='orange', alpha=0.7)
    ax5.set_xlabel('HTTP Method')
    ax5.set_ylabel('Count')
    ax5.set_title('HTTP Methods Used')
    ax5.set_xticks(range(len(method_counts)))
    ax5.set_xticklabels(method_counts.index)

    # Add value labels
    for i, bar in enumerate(bars5):
        height = bar.get_height()
        ax5.text(bar.get_x() + bar.get_width() / 2., height + max(method_counts.values) * 0.01,
                 f'{int(height)}', ha='center', va='bottom', fontsize=8)

    # 6. Error Rate Analysis
    ax6 = plt.subplot(2, 3, 6)
    error_rate = (df['status'] >= 400).mean() * 100
    success_rate = (df['status'] < 400).mean() * 100

    ax6.pie([error_rate, success_rate], labels=['Errors (4xx/5xx)', 'Success (1xx-3xx)'],
            colors=['lightcoral', 'lightgreen'], autopct='%1.1f%%', startangle=90)
    ax6.set_title('Request Success vs Error Rate')

    plt.tight_layout()

    # Save the plot
    filename = f'web_analysis_{run_name.lower().replace(" ", "_")}.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    print(f"Saved visualization: {filename}")

    plt.show()

    return df


def compare_runs(df1, df2, run1_name, run2_name):
    """Compare credential patterns between two runs"""
    print(f"\n=== Run Comparison: {run1_name} vs {run2_name} ===")

    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle(f'Run Comparison: {run1_name} vs {run2_name}', fontsize=16, fontweight='bold')

    # 1. Total attempts comparison
    totals = [len(df1), len(df2)]
    ax1.bar([run1_name, run2_name], totals, color=['steelblue', 'darkred'], alpha=0.7)
    ax1.set_ylabel('Total Attempts')
    ax1.set_title('Total Login Attempts')
    for i, v in enumerate(totals):
        ax1.text(i, v + max(totals) * 0.01, str(v), ha='center', va='bottom', fontweight='bold')

    # 2. Success rate comparison
    success_rates = [df1['success'].mean() * 100, df2['success'].mean() * 100]
    ax2.bar([run1_name, run2_name], success_rates, color=['lightgreen', 'lightcoral'], alpha=0.7)
    ax2.set_ylabel('Success Rate (%)')
    ax2.set_title('Login Success Rate')
    for i, v in enumerate(success_rates):
        ax2.text(i, v + max(success_rates) * 0.01, f'{v:.1f}%', ha='center', va='bottom', fontweight='bold')

    # 3. Unique usernames comparison
    unique_users = [df1['username'].nunique(), df2['username'].nunique()]
    ax3.bar([run1_name, run2_name], unique_users, color=['purple', 'orange'], alpha=0.7)
    ax3.set_ylabel('Unique Usernames')
    ax3.set_title('Username Diversity')
    for i, v in enumerate(unique_users):
        ax3.text(i, v + max(unique_users) * 0.01, str(v), ha='center', va='bottom', fontweight='bold')

    # 4. Attack duration comparison
    durations = []
    for df, name in [(df1, run1_name), (df2, run2_name)]:
        if not df.empty:
            duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 60
            durations.append(duration)
        else:
            durations.append(0)

    ax4.bar([run1_name, run2_name], durations, color=['teal', 'gold'], alpha=0.7)
    ax4.set_ylabel('Duration (minutes)')
    ax4.set_title('Attack Duration')
    for i, v in enumerate(durations):
        ax4.text(i, v + max(durations) * 0.01, f'{v:.1f}m', ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()
    plt.savefig('run_comparison.png', dpi=300, bbox_inches='tight')
    print("Saved comparison visualization: run_comparison.png")
    plt.show()


def main():
    """Main analysis function"""
    print("Enhanced Attack Pattern Analyzer - Lightweight IoT Honeypot Project")
    print("=" * 70)

    # Load SSH data files
    print("Loading SSH data files...")
    run1_data = load_cowrie_data('cowrie_clean.json')
    run2_data = load_cowrie_data('cowrie_run2.json')

    # Load Web data files
    print("Loading web attack data files...")
    run1_web = load_web_data('web_probe_clean.txt')
    run2_web = load_web_data('web_probe_run2.txt')

    # Extract login attempts
    run1_df = extract_login_attempts(run1_data) if run1_data else pd.DataFrame()
    run2_df = extract_login_attempts(run2_data) if run2_data else pd.DataFrame()

    # Analyze SSH attacks
    if not run1_df.empty:
        analyze_credentials(run1_df, "Run 1")

    if not run2_df.empty:
        analyze_credentials(run2_df, "Run 2")

    # Analyze Web attacks
    if run1_web:
        analyze_web_attacks(run1_web, "Run 1")

    if run2_web:
        analyze_web_attacks(run2_web, "Run 2")

    # Compare SSH runs if both exist
    if not run1_df.empty and not run2_df.empty:
        compare_runs(run1_df, run2_df, "Run 1", "Run 2")

    print("\n" + "=" * 70)
    print("Analysis complete! Check the generated PNG files for visualizations.")
    print("SSH Analysis: credential_analysis_run_1.png, credential_analysis_run_2.png")
    print("Web Analysis: web_analysis_run_1.png, web_analysis_run_2.png")
    print("Comparison: run_comparison.png")


if __name__ == "__main__":
    main()
