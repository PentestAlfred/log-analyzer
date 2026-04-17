import re
import os
import argparse
from collections import Counter
from datetime import datetime


# ── SETTINGS ────────────────────────────────────────────────────────────────
FAILED_LOGIN_THRESHOLD = 3
REPORT_FILE = "security_report.txt"


# ── LOG PROFILES ─────────────────────────────────────────────────────────────
LOG_PROFILES = {
    "auth": {
        "failure_keywords": [
            "Failed password", "FAILED LOGIN", "authentication failure",
            "Invalid user", "Connection closed by invalid user", "error: PAM",
        ],
        "success_keywords": [
            "Accepted password", "Accepted publickey", "session opened", "New session",
        ],
        "description": "SSH Authentication Log"
    },
    "ssl": {
        "failure_keywords": [
            "SSL_ERROR", "handshake failure", "handshake_failure",
            "certificate verify failed", "SSL alert", "unknown ca",
            "bad certificate", "decrypt error", "no shared cipher",
        ],
        "success_keywords": [
            "SSL established", "Connection established", "Session-ID",
            "Cipher:", "connected",
        ],
        "description": "SSL/TLS Security Log"
    },
    "apache": {
        "failure_keywords": ["404", "403", "401", "400", "500", "error"],
        "success_keywords": ["200", "201", "302"],
        "description": "Apache Web Server Log"
    },
    "nginx": {
        "failure_keywords": ["404", "403", "401", "400", "500", "error"],
        "success_keywords": ["200", "201"],
        "description": "Nginx Web Server Log"
    },
    "firewall": {
        "failure_keywords": ["BLOCK", "DENY", "DROP", "REJECT", "blocked", "denied"],
        "success_keywords": ["ALLOW", "ACCEPT", "PASS"],
        "description": "Firewall Log"
    },
    "syslog": {
        "failure_keywords": ["error", "failed", "denied", "critical", "warning"],
        "success_keywords": ["started", "success", "completed"],
        "description": "System Log (syslog)"
    },
}

GENERIC_PROFILE = {
    "failure_keywords": [
        "error", "fail", "failed", "denied", "blocked",
        "invalid", "unauthorized", "refused", "attack", "alert"
    ],
    "success_keywords": [
        "success", "accepted", "connected", "established", "allowed", "200", "201"
    ],
    "description": "Generic / Unknown Log"
}


# ── CLI INPUT HANDLER ────────────────────────────────────────────────────────
def get_log_file():
    parser = argparse.ArgumentParser(
        description="Universal Log File Analyzer (SOC Tool)"
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to log file for analysis"
    )

    args = parser.parse_args()

    if args.file:
        return args.file

    return input("Enter log file path: ").strip()


# ── STEP 1: DETECT LOG TYPE ──────────────────────────────────────────────────
def detect_log_type(filepath):
    filename = os.path.basename(filepath).lower()

    for log_type, profile in LOG_PROFILES.items():
        if log_type in filename:
            print(f"[✓] Detected log type: {profile['description']} (filename match)")
            return profile

    try:
        with open(filepath, "r", errors="ignore") as f:
            sample = " ".join([f.readline() for _ in range(20)]).lower()

        for log_type, profile in LOG_PROFILES.items():
            for keyword in profile["failure_keywords"][:3]:
                if keyword.lower() in sample:
                    print(f"[✓] Detected log type: {profile['description']} (content match)")
                    return profile
    except Exception:
        pass

    print("[!] Using generic log profile")
    return GENERIC_PROFILE


# ── STEP 2: READ LOG FILE ────────────────────────────────────────────────────
def read_log_file(filepath):
    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
        print(f"[✓] Loaded {len(lines)} lines from '{filepath}'")
        return lines
    except FileNotFoundError:
        print(f"[✗] File not found: {filepath}")
        return []


# ── STEP 3: EXTRACT IP ───────────────────────────────────────────────────────
def extract_ip(line):
    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    if match:
        ip = match.group(1)
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                return ip
    return None


# ── STEP 4: SCAN LOGS ────────────────────────────────────────────────────────
def scan_lines(lines, profile):
    failure_ips = []
    success_ips = []
    failure_lines = []

    for line in lines:
        line_lower = line.lower()

        is_failure = any(k.lower() in line_lower for k in profile["failure_keywords"])
        is_success = any(k.lower() in line_lower for k in profile["success_keywords"])

        ip = extract_ip(line)

        if is_failure:
            if ip:
                failure_ips.append(ip)
            failure_lines.append(line.strip())

        if is_success and ip:
            success_ips.append(ip)

    print(f"[✓] Suspicious lines: {len(failure_lines)}")
    print(f"[✓] Success events: {len(success_ips)}")

    return failure_ips, success_ips, failure_lines


# ── STEP 5: FLAG IPS ─────────────────────────────────────────────────────────
def flag_suspicious_ips(failure_ips, threshold):
    ip_counts = Counter(failure_ips)
    suspicious = {ip: c for ip, c in ip_counts.items() if c >= threshold}

    if suspicious:
        print(f"[⚠] Suspicious IPs detected: {len(suspicious)}")
    else:
        print("[✓] No suspicious IPs found")

    return ip_counts, suspicious


# ── STEP 6: COMPROMISED DETECTION ────────────────────────────────────────────
def detect_compromised(failure_ips, success_ips, suspicious):
    success_set = set(success_ips)
    return [ip for ip in suspicious if ip in success_set]


# ── STEP 7: REPORT GENERATION ────────────────────────────────────────────────
def generate_report(filepath, profile, ip_counts, suspicious, compromised, failure_lines, total_lines):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "=" * 60

    report = f"""
{sep}
 LOG FILE ANALYZER - SECURITY REPORT
 File     : {os.path.basename(filepath)}
 Log Type : {profile['description']}
 Generated: {now}
{sep}

[1] OVERVIEW
 Total lines            : {total_lines}
 Suspicious lines       : {len(failure_lines)}
 Unique IPs             : {len(ip_counts)}
 Suspicious IPs         : {len(suspicious)}
 Compromised IPs        : {len(compromised)}

[2] TOP OFFENDING IPS
"""

    for ip, count in ip_counts.most_common(10):
        flag = " ⚠" if ip in suspicious else ""
        report += f" {ip:<18} {count} events{flag}\n"

    report += f"""

[3] SUSPICIOUS IPS (>= {FAILED_LOGIN_THRESHOLD})
"""

    for ip, count in suspicious.items():
        report += f" ⚠ {ip} -> {count} events\n"

    report += "\n[4] COMPROMISED IPS\n"
    if compromised:
        for ip in compromised:
            report += f" ALERT: {ip} had both failure + success\n"
    else:
        report += " None detected\n"

    report += "\n[5] SAMPLE LOGS\n"
    for line in failure_lines[:5]:
        report += f" {line[:120]}\n"

    report += f"""

[6] RECOMMENDATIONS
 - Block repeated malicious IPs
 - Investigate compromised hosts
 - Enable real-time monitoring
 - Patch vulnerable services

{sep}
 END REPORT
{sep}
"""

    print(report)

    with open(REPORT_FILE, "w") as f:
        f.write(report)

    print(f"[✓] Report saved to {REPORT_FILE}")


# ── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 60)
    print(" LOG FILE ANALYZER")
    print(" SOC / Cybersecurity Monitoring Tool")
    print("=" * 60 + "\n")

    log_file = get_log_file()

    profile = detect_log_type(log_file)
    lines = read_log_file(log_file)

    if not lines:
        return

    failure_ips, success_ips, failure_lines = scan_lines(lines, profile)
    ip_counts, suspicious = flag_suspicious_ips(failure_ips, FAILED_LOGIN_THRESHOLD)
    compromised = detect_compromised(failure_ips, success_ips, suspicious)

    generate_report(
        log_file,
        profile,
        ip_counts,
        suspicious,
        compromised,
        failure_lines,
        len(lines)
    )


if __name__ == "__main__":
    main()
