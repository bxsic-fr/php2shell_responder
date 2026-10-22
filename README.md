# php2shell_responder

Log detector for **PHP2SHELL**: two PHP use-after-free bugs in the
`session.upload_progress` handling. Read-only, offline, Python 3 standard library only.

## CVE

| CVE | Bug | Surface |
|---|---|---|
| CVE-2026-109618 | Use-after-free of the serialization context (`BG(serialize)`) | `php_session_rfc1867_callback`, before RINIT, unauthenticated |
| CVE-2026-109619 | Use-after-free of the unserialization context (`BG(unserialize)`) | same |

Fixed versions as announced: PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 (or vendor
backports). Verify against the official PHP advisory before any external use.

## Usage

```bash
python3 php2shell_detect.py /path/to/log_copies/
python3 php2shell_detect.py /path/to/logs/ --json report.json --csv report.csv
python3 php2shell_detect.py /path/to/logs/ --verbose --min-severity MEDIUM
```

Options: `--burst-window SECONDS` (default 20) and `--burst-threshold N`
(default 4) for the P2S-013 burst rule, `--min-severity`, `--json`, `--csv`,
`--verbose`.

Supported inputs: Apache and Nginx (access and error logs), PHP-FPM, syslog.
Run it on **copies** of the logs, never on the originals.

## Rules

| ID | Detection | Severity |
|---|---|---|
| P2S-001 | Large POST to a PHP endpoint | MEDIUM/HIGH |
| P2S-002 | HTTP 500 after a POST to PHP | HIGH |
| P2S-003 | PHP memory exhaustion | HIGH |
| P2S-004 | SIGSEGV / segmentation fault (FIRE-phase kill) | CRITICAL |
| P2S-005 | `session.upload_progress` in an error log | HIGH |
| P2S-006 | PHP-FPM worker killed by SIGSEGV | CRITICAL |
| P2S-008 | PHP code in a PHPSESSID cookie | CRITICAL |
| P2S-009 | Apache child crash | CRITICAL |
| P2S-010 | `PHP_SESSION_UPLOAD_PROGRESS` in a request | CRITICAL |
| P2S-011 | Pre-RINIT OOM (`in Unknown on line 0`) | CRITICAL |
| P2S-012 | Invalid session ID probe | MEDIUM/HIGH |
| P2S-013 | POST burst with a trigger, correlated when possible | MEDIUM/HIGH |
| P2S-014 | Session data read/write failure | MEDIUM |
| P2S-015 | Oversized POST rejected | MEDIUM |
| P2S-016 | Stale session state across requests | HIGH |
| P2S-017 | PoC boundary or probe marker visible | HIGH |
| P2S-018 | Request referencing `sess_<id>` (HIGH under an include-like parameter) | MEDIUM/HIGH |
| P2S-019 | PHP code near the upload-progress field | HIGH |
| P2S-020 | Session decode error | MEDIUM |
| P2S-021 | Upload followed by a request for the same session file | HIGH |

A finding is a lead, not proof of code execution. Check the raw logs, the PHP
configuration and the host before concluding.

## Scope

Defensive use and CSIRT investigation on logs you are authorized to analyze.
The detector sends no network requests.

## License

MIT, see [LICENSE](LICENSE). Commercial use is allowed, provided the copyright
notice and license are kept (source attribution).
