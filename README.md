# 🛡️ Network Security Port Scanner (CyberPort Scanner Pro)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![WebSockets](https://img.shields.io/badge/WebSockets-Real--time-brightgreen.svg)](https://websockets.readthedocs.io/)
[![Rich CLI](https://img.shields.io/badge/CLI-Rich%20Terminal-orange.svg)](https://github.com/Textualize/rich)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance, multi-threaded network security port scanner and host intelligence engine. Features both a modern **real-time Web Dashboard** (FastAPI + WebSockets) and a **rich interactive Terminal CLI**, complete with service identification, banner grabbing, and security risk assessment.

---

## 📑 Table of Contents

- [Features](#-features)
- [Architecture & File Structure](#-architecture--file-structure)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage Guide](#-usage-guide)
  - [1. Web Dashboard (GUI)](#1-web-dashboard-gui)
  - [2. Interactive CLI Scanner](#2-interactive-cli-scanner)
  - [3. Minimal Standalone Script](#3-minimal-standalone-script)
- [Scan Profiles & Presets](#-scan-profiles--presets)
- [Security Risk Ratings](#-security-risk-ratings)
- [REST & WebSocket API](#-rest--websocket-api)
- [Ethical Use & Disclaimer](#-ethical-use--disclaimer)
- [License](#-license)

---

## 🚀 Features

- **⚡ Multi-Threaded Engine**: Concurrent socket connections powered by Python's `concurrent.futures.ThreadPoolExecutor` for ultra-fast scanning (100–500+ ports/second).
- **🌐 Modern Web Dashboard**: 
  - Real-time live streaming over WebSockets without page reload.
  - Interactive metrics: scanned count, open ports, elapsed time, and scanning speed.
  - Live activity log and filterable open-ports table with color-coded risk tags.
  - Auto-launches in the default web browser upon startup.
- **💻 Rich Terminal CLI**:
  - Animated spinners, progress bars, and ETA calculations using `rich`.
  - Beautiful tabular results displaying open ports, protocols, services, and latency.
- **🔍 Deep Service Fingerprinting & Banner Grabbing**:
  - Probes HTTP/HTTPS headers (`Server:`), TLS handshake parameters (version & cipher suites), and raw service banners.
  - Automatic reverse DNS (PTR record) and round-trip latency calculation.
- **⚠️ Integrated Risk Assessment**:
  - Built-in database classifying vulnerable or high-risk exposed services (e.g., Telnet, SMB, Redis, MongoDB, RDP, VNC) into **Critical**, **High**, **Medium**, and **Low** security risk tiers.
- **🎯 Flexible Port Targeting**:
  - 6 curated scan presets or custom port ranges (e.g., `80,443,8000-8080`).

---

## 📂 Architecture & File Structure

```text
Network-Security-Port-Scanner/
│
├── app.py               # FastAPI backend & WebSocket server for the Web Dashboard
├── scanner_engine.py    # Multi-threaded scanning core, port DB & service fingerprinting
├── scanner_cli.py       # Terminal UI with rich tables, live progress bars, and flags
├── port_scanner.py      # Standalone lightweight beginner-friendly scanner
├── run.bat              # One-click Windows batch launcher for the Web Dashboard
├── requirements.txt     # Python package dependencies
├── .gitignore           # Git ignore rules for clean repository state
│
└── static/              # Web Dashboard frontend assets
    ├── index.html       # Single-page dashboard HTML interface
    ├── style.css        # Responsive dark-theme cyber UI styling
    └── app.js           # WebSocket client & real-time UI state manager
```

---

## 📋 Requirements

- **Python**: Version 3.8 or higher
- **Operating System**: Windows, macOS, or Linux
- **Dependencies**: Listed in `requirements.txt` (`fastapi`, `uvicorn`, `pydantic`, `rich`)

---

## 🔧 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Anurandh-byte/Network-Security-Port-Scanner.git
   cd Network-Security-Port-Scanner
   ```

2. **(Optional) Create and activate a virtual environment:**
   - **Windows:**
     ```powershell
     python -m venv venv
     .\venv\Scripts\activate
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🖥️ Usage Guide

### 1. Web Dashboard (GUI)

Start the local web application server:

- **On Windows:** Double-click `run.bat` or run:
  ```powershell
  python app.py
  ```
- **On Linux / macOS:**
  ```bash
  python3 app.py
  ```

Your browser will automatically open:
```text
http://127.0.0.1:8000
```

#### Dashboard Capabilities:
- Enter target IP or hostname (e.g. `127.0.0.1`, `scanme.nmap.org`).
- Select a preset profile or enter custom port ranges.
- Adjust concurrency (threads) and socket timeout.
- Start and stop scans on demand with instantaneous cancellation.
- Inspect detailed service banners, risk levels, and response latency in real-time.

---

### 2. Interactive CLI Scanner

Run the rich command-line scanner directly in your terminal:

```bash
# Interactive mode (prompts for target and preset)
python scanner_cli.py

# Quick scan on default top 20 ports
python scanner_cli.py 127.0.0.1

# Scan custom port range with 100 threads
python scanner_cli.py 192.168.1.1 --range 1-1024 --threads 100 --timeout 0.2

# Scan using a built-in profile
python scanner_cli.py example.com --preset databases
```

#### CLI Options:
| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target IP address or domain name | `127.0.0.1` |
| `-p`, `--preset` | Preset profile (`top20`, `top100`, `standard`, `web`, `databases`, `remote_admin`) | `top20` |
| `-r`, `--range` | Custom port list or range (e.g. `22,80,443` or `1-1024`) | *None* |
| `-t`, `--threads` | Worker threads for concurrent socket scanning | `80` |
| `--timeout` | Socket connection timeout in seconds | `0.25` |

---

### 3. Minimal Standalone Script

If you need a zero-dependency script with no external packages:

```bash
python port_scanner.py
```
Scans standard system ports (1-1024) sequentially using native Python sockets.

---

## 🎯 Scan Profiles & Presets

| Preset Key | Profile Name | Description | Port Count |
|------------|--------------|-------------|------------|
| `top20` | **Top 20 Critical Ports** | High-priority scan of the most commonly attacked ports | 20 |
| `top100` | **Top 100 Common Ports** | Broad coverage of standard internet & enterprise service ports | 100 |
| `standard` | **Privileged Ports** | Complete sweep of all well-known system ports (1–1024) | 1,024 |
| `web` | **Web & Cloud Services** | HTTP, HTTPS, proxies, Node/React dev servers, and microservices | 18 |
| `databases` | **Databases & Caches** | MySQL, Postgres, MSSQL, Oracle, Redis, MongoDB, Kafka, Elastic | 14 |
| `remote_admin` | **Remote Administration** | SSH, Telnet, RDP, VNC, WinRM, NetBIOS, SMB, and SNMP | 15 |

---

## ⚠️ Security Risk Ratings

The scanner correlates detected open ports against an embedded vulnerability intelligence base:

- **🔴 Critical**: Unauthenticated or high-exploit services exposed directly (e.g., Redis `6379`, MongoDB `27017` with default open bindings).
- **🟠 High**: Remote admin consoles and database endpoints susceptible to brute-force or legacy exploits (e.g., Telnet `23`, SMB `445`, RDP `3389`, VNC `5900`, MSSQL `1433`).
- **🟡 Medium**: Cleartext protocols or management ports requiring verification (e.g., FTP `21`, POP3 `110`, IMAP `143`, WinRM `5986`).
- **🔵 Low / Info**: Standard secure protocols and public application ports (e.g., HTTPS `443`, SSH `22`, SMTPS `465`).

---

## 🔌 REST & WebSocket API

The FastAPI service exposes the following endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Serves the web dashboard UI |
| `GET` | `/api/presets` | Retrieves available scan presets and descriptions |
| `POST` | `/api/target-info` | Performs DNS resolution, reverse PTR lookup, and latency test |
| `POST` | `/api/scan` | Runs a synchronous scan job and returns full results JSON |
| `WS` | `/ws/scan` | Bidirectional WebSocket stream for real-time progress, batches, and cancellation |

---

## ⚖️ Ethical Use & Disclaimer

> [!WARNING]
> This tool is developed strictly for **authorized educational, security auditing, and defensive administrative purposes**. Scanning networks or systems without prior explicit permission from the owner is illegal and violates computer misuse laws in many jurisdictions. Always obtain proper authorization before scanning remote targets.

---

## 📄 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).
