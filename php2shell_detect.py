#!/usr/bin/env python3
"""
PHP2SHELL Log Detector — CVE-2026-109618 & CVE-2026-109619
CSIRT investigation tool to detect exploitation attempts in log files.

Detection is based on the actual exploitation mechanics documented by
JackalSyn (php2shell-reup), ikow/php2shell-poc, and murrez/php2shell:

  ARM phase:  multipart POST with huge filenames (1-2MB) + PHP_SESSION_UPLOAD_PROGRESS
              field + PHPSESSID cookie/form field → pre-RINIT OOM → "Allowed memory
              size exhausted ... in Unknown on line 0" → HTTP 500, worker survives

  FIRE phase: follow-up multipart POSTs with spray parts (s[], t[] arrays) that
              reclaim the freed context → SIGSEGV / worker kill

Key log indicators (in order of specificity):
  1. "in Unknown on line 0" — pre-RINIT OOM fatal (THE smoking gun)
  2. "child pid N exit signal Segmentation fault (11)" — UAF crash
  3. "Session ID is too long or contains illegal characters" — invalid session probes
  4. "Failed to read/write session data" — session manipulation
  5. Rapid POST sequences to PHP endpoints with multipart/form-data
  6. HTTP 500 responses on PHP endpoints after POST

Usage:
    python3 php2shell_detect.py /path/to/logs/
    python3 php2shell_detect.py /path/to/logs/ --json report.json --csv report.csv
    python3 php2shell_detect.py /path/to/logs/ --verbose
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    rule_id: str
    severity: str
    cve: str
    machine: str
    file_path: str
    line_number: int
    raw_line: str
    description: str
    source_ip: Optional[str] = None
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    timestamp: Optional[str] = None
    session_id: Optional[str] = None
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Log format detection and parsing
# ---------------------------------------------------------------------------

APACHE_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)")?'
    r'(?:\s+"(?P<cookie>[^"]*)")?'
    r'(?:\s+(?P<content_type>\S+))?'
    r'(?:\s+(?P<bytes_in>\d+))?'
)

NGINX_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+-\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)"'
)

APACHE_ERROR_RE = re.compile(
    r'^\[(?P<timestamp>[^\]]+)\]\s+'
    r'(?:\[(?P<module>[^\]]*)\]\s+)?'
    r'(?:\[pid\s+(?P<pid>\d+)[^\]]*\]\s+)?'
    r'(?:\[client\s+(?P<client>[^\]]*)\]\s+)?'
    r'(?P<message>.*)'
)

PHP_FPM_RE = re.compile(
    r'^\[(?P<timestamp>[^\]]+)\]\s+'
    r'(?P<level>\S+):\s+'
    r'(?P<message>.*)'
)

SYSLOG_RE = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<program>[^\[]+)(?:\[(?P<pid>\d+)\])?\s*:\s*'
    r'(?P<message>.*)'
)


class LogType:
    APACHE_ACCESS = "apache_access"
    APACHE_ERROR = "apache_error"
    NGINX_ACCESS = "nginx_access"
    PHP_FPM = "php_fpm"
    SYSLOG = "syslog"
    UNKNOWN = "unknown"


def detect_log_type(filepath, sample_lines):
    name = os.path.basename(filepath).lower()

    if "access" in name and "error" not in name:
        for line in sample_lines:
            if APACHE_ACCESS_RE.match(line) or NGINX_ACCESS_RE.match(line):
                return LogType.NGINX_ACCESS if "nginx" in name else LogType.APACHE_ACCESS

    if "fpm" in name or "php-fpm" in name:
        for line in sample_lines:
            if PHP_FPM_RE.match(line):
                return LogType.PHP_FPM

    if "error" in name:
        for line in sample_lines:
            if APACHE_ERROR_RE.match(line):
                return LogType.APACHE_ERROR

    if "syslog" in name or "messages" in name or "kern" in name:
        for line in sample_lines:
            if SYSLOG_RE.match(line):
                return LogType.SYSLOG

    for line in sample_lines:
        if APACHE_ACCESS_RE.match(line):
            return LogType.APACHE_ACCESS
        if NGINX_ACCESS_RE.match(line):
            return LogType.NGINX_ACCESS
        if PHP_FPM_RE.match(line):
            return LogType.PHP_FPM
        if APACHE_ERROR_RE.match(line):
            return LogType.APACHE_ERROR
        if SYSLOG_RE.match(line):
            return LogType.SYSLOG

    return LogType.UNKNOWN


def parse_access_line(line):
    m = APACHE_ACCESS_RE.match(line) or NGINX_ACCESS_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    d["status"] = int(d.get("status", 0) or 0)
    return d


def parse_error_line(line):
    m = APACHE_ERROR_RE.match(line)
    return m.groupdict() if m else None


def parse_fpm_line(line):
    m = PHP_FPM_RE.match(line)
    return m.groupdict() if m else None


def parse_syslog_line(line):
    m = SYSLOG_RE.match(line)
    return m.groupdict() if m else None


def extract_machine_name(filepath, log_root):
    rel = os.path.relpath(filepath, log_root)
    parts = Path(rel).parts
    if len(parts) >= 2:
        return parts[0]
    stem = Path(filepath).stem
    for suffix in ["-access", "-error", "_access", "_error", ".access", ".error",
                   "-apache", "-nginx", "-fpm", "_apache", "_nginx", "_fpm"]:
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def extract_phpsessid(cookie_str):
    if not cookie_str:
        return None
    m = re.search(r'PHPSESSID=([^;\s]+)', cookie_str)
    return m.group(1) if m else None


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ---------------------------------------------------------------------------
# Detection rules — Access logs
# ---------------------------------------------------------------------------

def check_access_rules(parsed, raw_line, line_num, filepath, machine):
    findings = []
    if not parsed:
        return findings

    ip = parsed.get("ip", "")
    method = parsed.get("method", "")
    path = parsed.get("path", "")
    status = parsed.get("status", 0)
    cookie = parsed.get("cookie", "") or ""
    content_type = parsed.get("content_type", "") or ""
    useragent = parsed.get("useragent", "") or ""
    bytes_in_str = parsed.get("bytes_in", "") or ""
    timestamp = parsed.get("timestamp", "")
    session_id = extract_phpsessid(cookie)

    is_php = bool(re.search(r'\.php', path, re.IGNORECASE))
    is_post = method.upper() == "POST"
    is_multipart = "multipart" in content_type.lower()

    # P2S-010: PHP_SESSION_UPLOAD_PROGRESS in URL/query/body reference
    if "PHP_SESSION_UPLOAD_PROGRESS" in raw_line:
        findings.append(Finding(
            rule_id="P2S-010", severity="CRITICAL",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description="PHP_SESSION_UPLOAD_PROGRESS in request — direct php2shell indicator",
            source_ip=ip, endpoint=path, http_method=method,
            http_status=status, timestamp=timestamp, session_id=session_id,
        ))

    # P2S-008: PHPSESSID cookie contains PHP code
    if session_id and re.search(
            r'<\?php|<\?=|system\s*\(|exec\s*\(|passthru|shell_exec|eval\s*\(',
            session_id, re.IGNORECASE):
        findings.append(Finding(
            rule_id="P2S-008", severity="CRITICAL",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description="PHPSESSID cookie contains PHP code injection",
            source_ip=ip, endpoint=path, http_method=method,
            http_status=status, timestamp=timestamp, session_id=session_id,
        ))

    # P2S-002: HTTP 500 on PHP endpoint after POST (pre-RINIT OOM crash)
    if is_post and is_php and status == 500:
        findings.append(Finding(
            rule_id="P2S-002", severity="HIGH",
            cve="CVE-2026-109618",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description="HTTP 500 on PHP endpoint after POST — possible pre-RINIT OOM (ARM phase)",
            source_ip=ip, endpoint=path, http_method=method,
            http_status=status, timestamp=timestamp, session_id=session_id,
        ))

    # P2S-001: Large multipart POST to PHP endpoint (ARM phase uses 1-2MB filenames)
    if is_post and is_php:
        try:
            bytes_in = int(bytes_in_str) if bytes_in_str else 0
        except ValueError:
            bytes_in = 0
        if bytes_in > 500_000:
            sev = "HIGH" if bytes_in > 1_000_000 else "MEDIUM"
            findings.append(Finding(
                rule_id="P2S-001", severity=sev,
                cve="CVE-2026-109618 / CVE-2026-109619",
                machine=machine, file_path=filepath, line_number=line_num,
                raw_line=raw_line,
                description=f"Large POST to PHP endpoint ({bytes_in:,} bytes) — ARM phase uses 1-2MB filename payloads",
                source_ip=ip, endpoint=path, http_method=method,
                http_status=status, timestamp=timestamp, session_id=session_id,
                extra={"bytes_in": bytes_in},
            ))

    # P2S-013: Rapid POST burst from same IP (FIRE phase: multiple spray requests)
    # Tracked via post_tracker in scan_file, evaluated in correlate_findings

    return findings


# ---------------------------------------------------------------------------
# Detection rules — Error logs (Apache, PHP)
# ---------------------------------------------------------------------------

def check_error_rules(parsed, raw_line, line_num, filepath, machine):
    findings = []
    if not parsed:
        parsed = {"message": raw_line, "timestamp": "", "client": ""}

    msg = parsed.get("message", "")
    timestamp = parsed.get("timestamp", "")
    client = parsed.get("client", "") or ""
    client_ip = client.split(":")[0] if client else None

    # P2S-011: Pre-RINIT OOM — "in Unknown on line 0" (THE smoking gun)
    if re.search(r'in\s+Unknown\s+on\s+line\s+0', msg):
        sev = "CRITICAL"
        desc = "Pre-RINIT fatal error (in Unknown on line 0) — php2shell ARM phase signature"
        if re.search(r'memory\s+size.*exhausted', msg, re.IGNORECASE):
            desc = "Pre-RINIT OOM fatal (memory exhausted in Unknown on line 0) — php2shell ARM phase confirmed"
        findings.append(Finding(
            rule_id="P2S-011", severity=sev,
            cve="CVE-2026-109618",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line, description=desc,
            source_ip=client_ip, timestamp=timestamp,
        ))

    # P2S-004: Segmentation fault / signal 11 / Abort / heap corruption (FIRE phase kill)
    if re.search(r'Segmentation\s+fault|signal\s+11|SIGSEGV|zend_mm_heap\s+corrupted', msg, re.IGNORECASE):
        desc = "SIGSEGV detected — possible UAF exploitation (FIRE phase kill)"
        if re.search(r'zend_mm_heap\s+corrupted', msg, re.IGNORECASE):
            desc = "Zend MM heap corruption — UAF exploitation confirmed (FIRE phase)"
        findings.append(Finding(
            rule_id="P2S-004", severity="CRITICAL",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description=desc,
            source_ip=client_ip, timestamp=timestamp,
        ))

    # P2S-009: Apache child crash (SIGSEGV or Abort from heap corruption)
    if re.search(r'child\s+pid\s+\d+\s+exit\s+signal\s+(Segmentation\s+fault|Abort)', msg, re.IGNORECASE):
        sig_match = re.search(r'exit\s+signal\s+(\w[\w\s]*?)(?:\s*\(|,)', msg)
        sig_name = sig_match.group(1).strip() if sig_match else "unknown"
        findings.append(Finding(
            rule_id="P2S-009", severity="CRITICAL",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description=f"Apache child crashed with {sig_name} — UAF exploitation kill receipt",
            timestamp=timestamp,
        ))

    # P2S-003: Memory exhaustion (general — may not be pre-RINIT)
    if re.search(r'(Allowed\s+)?memory\s+size.*exhausted', msg, re.IGNORECASE):
        if not re.search(r'in\s+Unknown\s+on\s+line\s+0', msg):
            findings.append(Finding(
                rule_id="P2S-003", severity="HIGH",
                cve="CVE-2026-109618",
                machine=machine, file_path=filepath, line_number=line_num,
                raw_line=raw_line,
                description="PHP memory exhaustion — potential OOM trigger for CVE-2026-109618",
                source_ip=client_ip, timestamp=timestamp,
            ))

    # P2S-005: session.upload_progress in error message
    if re.search(r'session[._]upload[._]progress', msg, re.IGNORECASE):
        findings.append(Finding(
            rule_id="P2S-005", severity="HIGH",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description="session.upload_progress referenced in error log",
            source_ip=client_ip, timestamp=timestamp,
        ))

    # P2S-012: "Session ID is too long or contains illegal characters"
    if re.search(r'Session\s+ID\s+is\s+too\s+long\s+or\s+contains\s+illegal\s+characters', msg, re.IGNORECASE):
        findings.append(Finding(
            rule_id="P2S-012", severity="MEDIUM",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description="Invalid session ID probe — php2shell exploit uses controlled PHPSESSID values",
            source_ip=client_ip, timestamp=timestamp,
        ))

    # P2S-014: "Failed to read/write session data"
    if re.search(r'Failed\s+to\s+(read|write)\s+session\s+data', msg, re.IGNORECASE):
        findings.append(Finding(
            rule_id="P2S-014", severity="MEDIUM",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description="Session data read/write failure — may indicate session manipulation during exploit",
            source_ip=client_ip, timestamp=timestamp,
        ))

    # P2S-015: "POST Content-Length exceeds the limit" (large body rejected)
    if re.search(r'POST\s+Content-Length\s+of\s+\d+\s+bytes\s+exceeds', msg, re.IGNORECASE):
        m = re.search(r'POST\s+Content-Length\s+of\s+(\d+)\s+bytes', msg)
        size = int(m.group(1)) if m else 0
        if size > 1_000_000:
            findings.append(Finding(
                rule_id="P2S-015", severity="MEDIUM",
                cve="CVE-2026-109618",
                machine=machine, file_path=filepath, line_number=line_num,
                raw_line=raw_line,
                description=f"Oversized POST rejected ({size:,} bytes) — may be ARM attempt blocked by post_max_size",
                source_ip=client_ip, timestamp=timestamp,
                extra={"content_length": size},
            ))

    # P2S-016: "Session ini settings cannot be changed when a session is active"
    if re.search(r'Session\s+ini\s+settings\s+cannot\s+be\s+changed\s+when.*active', msg, re.IGNORECASE):
        findings.append(Finding(
            rule_id="P2S-016", severity="HIGH",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description="Stale session state detected — bailout leaked PS(session_status)=active across requests",
            source_ip=client_ip, timestamp=timestamp,
        ))

    return findings


# ---------------------------------------------------------------------------
# Detection rules — PHP-FPM logs
# ---------------------------------------------------------------------------

def check_fpm_rules(parsed, raw_line, line_num, filepath, machine):
    findings = []
    if not parsed:
        parsed = {"message": raw_line, "timestamp": "", "level": ""}

    msg = parsed.get("message", "")
    timestamp = parsed.get("timestamp", "")

    # P2S-006: PHP-FPM child exited on signal 11 (SIGSEGV)
    if re.search(r'child\s+\d+\s+exited\s+on\s+signal\s+11|SIGSEGV', msg, re.IGNORECASE):
        findings.append(Finding(
            rule_id="P2S-006", severity="CRITICAL",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description="PHP-FPM worker crashed with SIGSEGV — possible UAF exploitation",
            timestamp=timestamp,
        ))

    findings.extend(check_error_rules(parsed, raw_line, line_num, filepath, machine))
    return findings


# ---------------------------------------------------------------------------
# Detection rules — Syslog
# ---------------------------------------------------------------------------

def check_syslog_rules(parsed, raw_line, line_num, filepath, machine):
    findings = []
    if not parsed:
        return findings

    msg = parsed.get("message", "")
    program = parsed.get("program", "").strip()
    hostname = parsed.get("hostname", "")
    timestamp = parsed.get("timestamp", "")

    if machine == Path(filepath).stem and hostname:
        machine = hostname

    php_programs = ("php", "php-fpm", "apache2", "httpd", "nginx", "lsphp")
    if program in php_programs:
        if re.search(r'Segmentation\s+fault|signal\s+11|SIGSEGV', msg, re.IGNORECASE):
            findings.append(Finding(
                rule_id="P2S-004", severity="CRITICAL",
                cve="CVE-2026-109618 / CVE-2026-109619",
                machine=machine, file_path=filepath, line_number=line_num,
                raw_line=raw_line,
                description=f"SIGSEGV in {program} (syslog) — possible UAF exploitation",
                timestamp=timestamp,
            ))

    if re.search(r'php.*segfault|httpd.*segfault|apache.*segfault|lsphp.*segfault', msg, re.IGNORECASE):
        findings.append(Finding(
            rule_id="P2S-004", severity="CRITICAL",
            cve="CVE-2026-109618 / CVE-2026-109619",
            machine=machine, file_path=filepath, line_number=line_num,
            raw_line=raw_line,
            description="PHP/Apache segfault in syslog — possible UAF exploitation",
            timestamp=timestamp,
        ))

    return findings


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

def correlate_findings(findings):
    by_machine = defaultdict(list)
    for f in findings:
        by_machine[f.machine].append(f)

    access_findings = [f for f in findings if f.rule_id in ("P2S-001", "P2S-002", "P2S-010")]
    crash_findings = [f for f in findings if f.rule_id in ("P2S-004", "P2S-006", "P2S-009", "P2S-011")]

    for af in access_findings:
        for cf in crash_findings:
            if af.machine == cf.machine:
                af.extra["correlated_crash"] = cf.rule_id
                af.extra["correlated_crash_line"] = cf.line_number
                break

    for machine, mfindings in by_machine.items():
        has_arm = any(f.rule_id == "P2S-011" for f in mfindings)
        has_kill = any(f.rule_id in ("P2S-004", "P2S-009", "P2S-006") for f in mfindings)
        has_session_probe = sum(1 for f in mfindings if f.rule_id == "P2S-012")

        if has_arm and has_kill:
            for f in mfindings:
                if f.rule_id in ("P2S-011", "P2S-004", "P2S-009"):
                    f.extra["attack_chain"] = "ARM+FIRE confirmed — full php2shell exploitation chain"

        if has_arm and not has_kill:
            arm_ips = {f.source_ip for f in mfindings if f.rule_id == "P2S-011" and f.source_ip}
            has_post_200 = any(
                f.rule_id == "P2S-002" or
                (f.http_status == 200 and f.http_method == "POST" and f.source_ip in arm_ips)
                for f in mfindings
            )
            if has_post_200 or len([f for f in mfindings if f.rule_id == "P2S-011"]) >= 3:
                for f in mfindings:
                    if f.rule_id == "P2S-011":
                        f.extra["attack_chain"] = "ARM without crash — possible successful RCE (no SIGSEGV = controlled write)"
                        f.extra["rce_warning"] = True

        if has_arm and has_session_probe >= 2:
            for f in mfindings:
                if f.rule_id == "P2S-012":
                    f.extra["attack_chain"] = "Session probing correlated with ARM phase"

        # Bulk session warnings from same client → elevate to HIGH
        session_by_client = defaultdict(int)
        for f in mfindings:
            if f.rule_id == "P2S-012" and f.source_ip:
                session_by_client[f.source_ip] += 1
        for f in mfindings:
            if f.rule_id == "P2S-012" and f.source_ip:
                count = session_by_client[f.source_ip]
                if count >= 4:
                    f.severity = "HIGH"
                    f.extra["session_probe_count"] = count
                    f.description = f"Bulk invalid session ID probes ({count}x) from {f.source_ip} — exploit reconnaissance"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_file(filepath, log_root, verbose=False):
    findings = []
    machine = extract_machine_name(filepath, log_root)

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            sample = []
            for i, line in enumerate(f):
                if i < 20:
                    sample.append(line.strip())
                if i >= 19:
                    break

        log_type = detect_log_type(filepath, sample)

        if log_type == LogType.UNKNOWN:
            if verbose:
                print(f"  [SKIP] {filepath} — unknown log format")
            return findings, log_type

        if verbose:
            print(f"  [SCAN] {filepath} — detected as {log_type} (machine: {machine})")

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_num, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line:
                    continue

                if log_type in (LogType.APACHE_ACCESS, LogType.NGINX_ACCESS):
                    parsed = parse_access_line(line)
                    findings.extend(check_access_rules(parsed, line, line_num, filepath, machine))
                elif log_type == LogType.APACHE_ERROR:
                    parsed = parse_error_line(line)
                    findings.extend(check_error_rules(parsed, line, line_num, filepath, machine))
                elif log_type == LogType.PHP_FPM:
                    parsed = parse_fpm_line(line)
                    findings.extend(check_fpm_rules(parsed, line, line_num, filepath, machine))
                elif log_type == LogType.SYSLOG:
                    parsed = parse_syslog_line(line)
                    findings.extend(check_syslog_rules(parsed, line, line_num, filepath, machine))

    except PermissionError:
        print(f"  [ERROR] Permission denied: {filepath}", file=sys.stderr)
    except Exception as e:
        print(f"  [ERROR] {filepath}: {e}", file=sys.stderr)

    return findings, log_type


def scan_directory(log_root, verbose=False):
    all_findings = []
    file_count = 0
    type_counts = defaultdict(int)

    for dirpath, _, filenames in os.walk(log_root):
        for filename in sorted(filenames):
            filepath = os.path.join(dirpath, filename)

            if filename.endswith(".gz"):
                if verbose:
                    print(f"  [SKIP] {filepath} — gzip not supported")
                continue

            name_lower = filename.lower()
            ext = Path(filename).suffix.lower()
            is_log_like = (
                ext in {".log", ".txt", ".0", ".1", ".2", ".3", ".4", ".5"}
                or "log" in name_lower
                or "access" in name_lower
                or "error" in name_lower
                or "syslog" in name_lower
                or "messages" in name_lower
                or "fpm" in name_lower
                or ext == ""
            )

            if not is_log_like:
                continue

            file_count += 1
            findings, log_type = scan_file(filepath, log_root, verbose)
            type_counts[log_type] += 1
            all_findings.extend(findings)

    return all_findings, file_count, dict(type_counts)


def deduplicate_findings(findings):
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[96m",
    "LOW":      "\033[37m",
    "INFO":     "\033[90m",
}
RESET = "\033[0m"

RULE_DESCRIPTIONS = {
    "P2S-001": "Large POST to PHP endpoint (ARM phase payload)",
    "P2S-002": "HTTP 500 after POST to PHP (pre-RINIT OOM crash)",
    "P2S-003": "PHP memory exhaustion",
    "P2S-004": "SIGSEGV / heap corruption / Abort (FIRE phase kill)",
    "P2S-005": "session.upload_progress in error log",
    "P2S-006": "PHP-FPM worker SIGSEGV",
    "P2S-008": "PHPSESSID contains PHP code",
    "P2S-009": "Apache child SIGSEGV / Abort crash",
    "P2S-010": "PHP_SESSION_UPLOAD_PROGRESS in request",
    "P2S-011": "Pre-RINIT OOM ('in Unknown on line 0') — SMOKING GUN",
    "P2S-012": "Invalid session ID probe",
    "P2S-014": "Session data read/write failure",
    "P2S-015": "Oversized POST rejected (ARM attempt blocked)",
    "P2S-016": "Stale session state (bailout leak)",
}


def print_console_report(findings, file_count, type_counts, verbose=False):
    print()
    print("=" * 70)
    print("  PHP2SHELL DETECTOR — CVE-2026-109618 & CVE-2026-109619")
    print("  Based on JackalSyn/ikow/murrez exploitation analysis")
    print("=" * 70)
    print()
    print(f"  Files scanned: {file_count}")
    for lt, cnt in sorted(type_counts.items()):
        print(f"    {lt}: {cnt}")
    print(f"  Total findings: {len(findings)}")
    print()

    if not findings:
        print("  [+] No PHP2SHELL indicators detected.")
        print()
        return

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule_id))

    by_severity = defaultdict(int)
    by_machine = defaultdict(list)
    by_rule = defaultdict(int)
    for f in findings:
        by_severity[f.severity] += 1
        by_machine[f.machine].append(f)
        by_rule[f.rule_id] += 1

    print("  Summary by severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in by_severity:
            color = SEVERITY_COLORS.get(sev, "")
            print(f"    {color}{sev}{RESET}: {by_severity[sev]}")
    print()

    print("  Summary by rule:")
    for rule_id in sorted(by_rule):
        desc = RULE_DESCRIPTIONS.get(rule_id, "")
        print(f"    {rule_id}: {by_rule[rule_id]:>3}x  {desc}")
    print()

    print("  Summary by machine:")
    for machine, mfindings in sorted(by_machine.items()):
        crits = sum(1 for f in mfindings if f.severity == "CRITICAL")
        highs = sum(1 for f in mfindings if f.severity == "HIGH")
        chain = any(f.extra.get("attack_chain") for f in mfindings)
        rce_warn = any(f.extra.get("rce_warning") for f in mfindings)
        if rce_warn:
            chain_label = " [ARM WITHOUT CRASH — POSSIBLE RCE]"
        elif chain:
            chain_label = " [FULL CHAIN DETECTED]"
        else:
            chain_label = ""
        print(f"    {machine}: {len(mfindings)} findings "
              f"({crits} critical, {highs} high){chain_label}")
    print()

    print("-" * 70)
    print("  DETAILED FINDINGS")
    print("-" * 70)
    print()

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "")
        print(f"  {color}[{f.severity}]{RESET} {f.rule_id} | {f.cve}")
        print(f"    Machine:  {f.machine}")
        print(f"    File:     {f.file_path}:{f.line_number}")
        print(f"    Desc:     {f.description}")
        if f.source_ip:
            parts = [f"IP: {f.source_ip}"]
            if f.http_method:
                parts.append(f"{f.http_method} {f.endpoint}")
            if f.http_status:
                parts.append(f"HTTP {f.http_status}")
            if f.session_id:
                sid = f.session_id[:40] + ("..." if len(f.session_id) > 40 else "")
                parts.append(f"Session: {sid}")
            print(f"    Context:  {' | '.join(parts)}")
        if f.timestamp:
            print(f"    Time:     {f.timestamp}")
        truncated = f.raw_line[:200] + ("..." if len(f.raw_line) > 200 else "")
        print(f"    Log:      {truncated}")
        if f.extra:
            for k, v in f.extra.items():
                print(f"    {k}: {v}")
        print()


def export_json(findings, output_path):
    data = {
        "tool": "php2shell_detect",
        "version": "2.0.0",
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "rules": RULE_DESCRIPTIONS,
        "findings": [{**asdict(f), "raw_line": f.raw_line[:1000]} for f in findings],
    }
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=2, ensure_ascii=False)
    print(f"  [*] JSON report written to: {output_path}")


def export_csv(findings, output_path):
    fieldnames = [
        "rule_id", "severity", "cve", "machine", "file_path", "line_number",
        "description", "source_ip", "endpoint", "http_method", "http_status",
        "timestamp", "session_id", "raw_line",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames,
                                extrasaction="ignore", quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for f in findings:
            row = asdict(f)
            row["raw_line"] = f.raw_line[:500]
            writer.writerow(row)
    print(f"  [*] CSV report written to: {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PHP2SHELL Log Detector v2.0 (CVE-2026-109618 & CVE-2026-109619)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Rules (16 detection patterns):
  P2S-001  Large POST to PHP endpoint (ARM payload)           MEDIUM/HIGH
  P2S-002  HTTP 500 after POST to PHP                         HIGH
  P2S-003  PHP memory exhaustion                              HIGH
  P2S-004  SIGSEGV / Segmentation fault (FIRE kill)           CRITICAL
  P2S-005  session.upload_progress in error log               HIGH
  P2S-006  PHP-FPM worker SIGSEGV                             CRITICAL
  P2S-008  PHPSESSID contains PHP code                        CRITICAL
  P2S-009  Apache child SIGSEGV crash                         CRITICAL
  P2S-010  PHP_SESSION_UPLOAD_PROGRESS in request             CRITICAL
  P2S-011  Pre-RINIT OOM ("in Unknown on line 0")             CRITICAL
  P2S-012  Invalid session ID probe                           MEDIUM/HIGH
  P2S-014  Session data read/write failure                    MEDIUM
  P2S-015  Oversized POST rejected                            MEDIUM
  P2S-016  Stale session state (bailout leak)                 HIGH

Examples:
  %(prog)s /var/log/
  %(prog)s /incident/logs/ --json report.json --csv report.csv
  %(prog)s /incident/logs/ --verbose --min-severity MEDIUM
        """,
    )
    parser.add_argument("log_dir", help="Directory containing log files to scan")
    parser.add_argument("--json", dest="json_output", metavar="FILE",
                        help="Export findings to JSON file")
    parser.add_argument("--csv", dest="csv_output", metavar="FILE",
                        help="Export findings to CSV file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed scan progress")
    parser.add_argument("--min-severity",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        default="LOW",
                        help="Minimum severity to report (default: LOW)")
    args = parser.parse_args()

    log_dir = os.path.abspath(args.log_dir)
    if not os.path.isdir(log_dir):
        print(f"[!] Not a directory: {log_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning: {log_dir}")

    all_findings, file_count, type_counts = scan_directory(log_dir, args.verbose)
    all_findings = deduplicate_findings(all_findings)
    correlate_findings(all_findings)

    min_sev = SEVERITY_ORDER.get(args.min_severity, 3)
    filtered = [f for f in all_findings if SEVERITY_ORDER.get(f.severity, 99) <= min_sev]

    print_console_report(filtered, file_count, type_counts, args.verbose)

    if args.json_output:
        export_json(filtered, args.json_output)
    if args.csv_output:
        export_csv(filtered, args.csv_output)

    sys.exit(1 if filtered else 0)


if __name__ == "__main__":
    main()
