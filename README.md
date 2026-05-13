# Log Analyser

A tool in C for analyzing and classifying system and web server logs. It supports multiple log formats and classifies events by type (security, performance, traffic, error) and severity.

---

## Project Structure

```
LogAnalyser/
├── src/                        # Main source code
│   ├── log_parser.h            # Structure definitions and parser prototypes
│   ├── log_parser.c            # Implementation of log parsers
│   ├── event_classifier.h      # Event type definitions and classifier prototypes
│   ├── event_classifier.c      # Implementation of event classification logic
│   ├── test_parsers.c          # Unit tests for parsers
│   ├── test_classifier.c       # Unit tests for the event classifier
│   └── Makefile                # Build system (Linux/macOS compatible)
│
├── generators/                 # Synthetic data generators for testing
│   ├── generate_apache_logs.c  # Apache Combined Log format generator
│   ├── generate_json_logs.c    # JSON structured log generator
│   ├── generate_syslog.c       # Syslog format generator (RFC 3164)
│   └── generate_nginx_error.c  # Nginx error log generator
│
├── datasets/                   # Automatically generated test datasets (created by Makefile)
│   ├── apache/                 # Generated Apache logs
│   ├── json_logs/              # Generated JSON logs
│   ├── syslog/                 # Generated Syslog logs
│   └── nginx/                  # Generated Nginx logs
│
└── docs/                       # Documentation
    └── events.md               # Complete guide to event classification
```

---

## Modules

### `src/log_parser` — Log Parsers

Responsible for parsing the four supported log sources, converting text lines into typed C structures.

| Format | Structure | Parsing Function |
|---|---|---|
| Apache Combined Log | `ApacheLogEntry` | `parse_apache_log()` |
| JSON Structured Log | `JSONLogEntry` | `parse_json_log()` |
| Syslog (RFC 3164) | `SyslogEntry` | `parse_syslog()` |
| Nginx Error Log | `NginxErrorEntry` | `parse_nginx_error()` |

Each entry captures relevant fields: source IP, timestamp, severity level, service, message, among others specific to each format.

---

### `src/event_classifier` — Event Classifier

Analyzes entries already processed by the parsers and classifies each event with one or more types (via bitmask) and a severity level.

**Event Types (`EventType`):**

| Flag | Valor | Descrição |
|---|---|---|
| `EVENT_SECURITY` | `1 << 0` | Authentication, denied access, attacks |
| `EVENT_PERFORMANCE` | `1 << 1` | Timeouts, server errors, crashes |
| `EVENT_TRAFFIC` | `1 << 2` | Traffic patterns and utilization |
| `EVENT_ERROR` | `1 << 3` | Application errors |
| `EVENT_NORMAL` | `1 << 4` | Normal operation |

**Severity Levels:**

| Level | Value | Description |
|---|---|---|
| INFO | 0 | Normal operation |
| LOW | 1 | Minor anomaly |
| MEDIUM | 2 | Requires attention |
| HIGH | 3 | Action required |
| CRITICAL | 4 | Critical failure |

**Analysis Modes (`AnalysisMode`):** The modes `MODE_SECURITY`, `MODE_PERFORMANCE`, `MODE_TRAFFIC` and `MODE_FULL` allow filtering events by category using bitwise OR.

---

### `generators/` — Dataset Generators

Independent C programs that produce realistic synthetic logs for testing. They take the number of lines/files to generate as an argument and write the output to `stdout` or to a folder.

| Generator | Compiled Binary | Output |
|---|---|---|
| `generate_apache_logs.c` | `gen_apache` | `datasets/apache/` |
| `generate_json_logs.c` | `gen_json` | `datasets/json_logs/` |
| `generate_syslog.c` | `gen_syslog` | `datasets/syslog/` |
| `generate_nginx_error.c` | `gen_nginx` | `datasets/nginx/` |

---

### `docs/eventos.md` — Classification Guide

Detailed documentation containing the classification logic for each log format, including reference tables for HTTP status codes, attack patterns (SQL Injection, XSS, Path Traversal), Syslog severity mapping, and practical examples of real-world scenarios (brute-force attacks, vulnerability scans, performance failure cascades).

---

## Build and Usage

The Makefile is located in `src/`. All commands must be executed from that folder.

```bash
cd src/

make              # Compiles everything (parsers, classifier, generators)
make datasets     # Generates test datasets (~1 MB)
make run-tests    # Compiles and runs the test suite
make clean        # Removes compiled binaries
make help         # Lists all available targets
```

To generate larger datasets (useful for performance testing):

```bash
make datasets-large    # Generates large datasets (~15 MB)
```

**Requirements:** GCC, Make, POSIX threads support (`-pthread`). Compatible with Linux and macOS.
