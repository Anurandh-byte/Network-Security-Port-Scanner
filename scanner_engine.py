import socket
import ssl
import time
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable

# Comprehensive Port Database with Service & Security Risk Ratings
PORT_DATABASE = {
    20: {"service": "FTP-DATA", "proto": "TCP", "risk": "Low", "desc": "FTP File Transfer Data"},
    21: {"service": "FTP", "proto": "TCP", "risk": "Medium", "desc": "File Transfer Protocol (Cleartext auth)"},
    22: {"service": "SSH", "proto": "TCP", "risk": "Low", "desc": "Secure Shell Remote Login"},
    23: {"service": "TELNET", "proto": "TCP", "risk": "High", "desc": "Telnet Remote Shell (Insecure cleartext)"},
    25: {"service": "SMTP", "proto": "TCP", "risk": "Medium", "desc": "Simple Mail Transfer (Email routing)"},
    53: {"service": "DNS", "proto": "UDP/TCP", "risk": "Low", "desc": "Domain Name System"},
    67: {"service": "DHCP", "proto": "UDP", "risk": "Low", "desc": "DHCP Server"},
    68: {"service": "DHCP-CLIENT", "proto": "UDP", "risk": "Low", "desc": "DHCP Client"},
    69: {"service": "TFTP", "proto": "UDP", "risk": "High", "desc": "Trivial FTP (No authentication)"},
    80: {"service": "HTTP", "proto": "TCP", "risk": "Low", "desc": "World Wide Web HTTP (Unencrypted)"},
    110: {"service": "POP3", "proto": "TCP", "risk": "Medium", "desc": "Post Office Protocol (Cleartext)"},
    119: {"service": "NNTP", "proto": "TCP", "risk": "Low", "desc": "Network News Transfer"},
    123: {"service": "NTP", "proto": "UDP", "risk": "Low", "desc": "Network Time Protocol"},
    135: {"service": "MSRPC / EPMAP", "proto": "TCP", "risk": "Medium", "desc": "Microsoft Windows RPC Endpoint Mapper"},
    137: {"service": "NETBIOS-NS", "proto": "UDP", "risk": "Medium", "desc": "NetBIOS Name Service"},
    138: {"service": "NETBIOS-DGM", "proto": "UDP", "risk": "Medium", "desc": "NetBIOS Datagram Service"},
    139: {"service": "NETBIOS-SSN", "proto": "TCP", "risk": "High", "desc": "NetBIOS Session Service (SMB legacy)"},
    143: {"service": "IMAP", "proto": "TCP", "risk": "Medium", "desc": "Internet Message Access Protocol"},
    161: {"service": "SNMP", "proto": "UDP", "risk": "High", "desc": "Simple Network Management Protocol (Check default communities)"},
    162: {"service": "SNMP-TRAP", "proto": "UDP", "risk": "Medium", "desc": "SNMP Trap"},
    389: {"service": "LDAP", "proto": "TCP", "risk": "Medium", "desc": "Lightweight Directory Access Protocol"},
    443: {"service": "HTTPS", "proto": "TCP", "risk": "Low", "desc": "HTTP over TLS/SSL (Secure Web)"},
    445: {"service": "MICROSOFT-DS", "proto": "TCP", "risk": "High", "desc": "SMB Direct / Windows File Sharing (Check EternalBlue/ransomware exposure)"},
    465: {"service": "SMTPS", "proto": "TCP", "risk": "Low", "desc": "SMTP over SSL"},
    514: {"service": "SYSLOG", "proto": "UDP", "risk": "Low", "desc": "System Logging Service"},
    587: {"service": "SUBMISSION", "proto": "TCP", "risk": "Low", "desc": "Email Message Submission"},
    636: {"service": "LDAPS", "proto": "TCP", "risk": "Low", "desc": "LDAP over TLS"},
    873: {"service": "RSYNC", "proto": "TCP", "risk": "Medium", "desc": "rsync File Synchronization"},
    993: {"service": "IMAPS", "proto": "TCP", "risk": "Low", "desc": "IMAP over TLS/SSL"},
    995: {"service": "POP3S", "proto": "TCP", "risk": "Low", "desc": "POP3 over TLS/SSL"},
    1080: {"service": "SOCKS-PROXY", "proto": "TCP", "risk": "High", "desc": "SOCKS Proxy Server"},
    1194: {"service": "OPENVPN", "proto": "UDP/TCP", "risk": "Low", "desc": "OpenVPN Tunnel"},
    1433: {"service": "MSSQL", "proto": "TCP", "risk": "High", "desc": "Microsoft SQL Server Database"},
    1521: {"service": "ORACLE-DB", "proto": "TCP", "risk": "High", "desc": "Oracle Database Listener"},
    2049: {"service": "NFS", "proto": "TCP/UDP", "risk": "High", "desc": "Network File System (Unauthenticated mount risk)"},
    2082: {"service": "CPANEL", "proto": "TCP", "risk": "Medium", "desc": "cPanel Web Hosting Manager"},
    2083: {"service": "CPANEL-SSL", "proto": "TCP", "risk": "Low", "desc": "cPanel over SSL"},
    3000: {"service": "NODEJS / GRAFANA", "proto": "TCP", "risk": "Medium", "desc": "Node.js / React / Grafana Dev Server"},
    3306: {"service": "MYSQL", "proto": "TCP", "risk": "High", "desc": "MySQL / MariaDB Database Server"},
    3389: {"service": "MS-RDP", "proto": "TCP", "risk": "High", "desc": "Microsoft Remote Desktop Protocol (Target for brute-force/BlueKeep)"},
    5000: {"service": "FLASK / DOCKER", "proto": "TCP", "risk": "Medium", "desc": "Python Flask / Docker Registry"},
    5432: {"service": "POSTGRESQL", "proto": "TCP", "risk": "High", "desc": "PostgreSQL Database Server"},
    5900: {"service": "VNC", "proto": "TCP", "risk": "High", "desc": "Virtual Network Computing (Remote Desktop)"},
    5985: {"service": "WINRM-HTTP", "proto": "TCP", "risk": "High", "desc": "Windows Remote Management (HTTP)"},
    5986: {"service": "WINRM-HTTPS", "proto": "TCP", "risk": "Medium", "desc": "Windows Remote Management (HTTPS)"},
    6379: {"service": "REDIS", "proto": "TCP", "risk": "Critical", "desc": "Redis In-Memory Data Store (Often unauthenticated RCE risk)"},
    8000: {"service": "HTTP-ALT", "proto": "TCP", "risk": "Low", "desc": "Alternative HTTP / Django / FastAPI"},
    8080: {"service": "HTTP-PROXY / TOMCAT", "proto": "TCP", "risk": "Medium", "desc": "HTTP Alternate / Apache Tomcat / Jenkins"},
    8443: {"service": "HTTPS-ALT", "proto": "TCP", "risk": "Low", "desc": "Alternative HTTPS / Tomcat SSL"},
    8888: {"service": "JUPYTER / HTTP", "proto": "TCP", "risk": "Medium", "desc": "Jupyter Notebook / Web Admin"},
    9000: {"service": "SONARQUBE / PHP-FPM", "proto": "TCP", "risk": "Medium", "desc": "SonarQube / Portainer / FastCGI"},
    9090: {"service": "PROMETHEUS / COCKPIT", "proto": "TCP", "risk": "Medium", "desc": "Prometheus Metrics / Linux Cockpit"},
    9200: {"service": "ELASTICSEARCH", "proto": "TCP", "risk": "High", "desc": "Elasticsearch REST API (Check open index access)"},
    27017: {"service": "MONGODB", "proto": "TCP", "risk": "Critical", "desc": "MongoDB NoSQL Database (Check unauthenticated access)"},
}

PRESETS = {
    "top20": {
        "name": "Top 20 Critical Ports",
        "description": "Fast scan of the 20 most frequently targeted ports",
        "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 27017]
    },
    "top100": {
        "name": "Top 100 Common Ports",
        "description": "Scans 100 most standard internet and network service ports",
        "ports": [
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139,
            143, 161, 162, 179, 199, 389, 443, 445, 465, 514, 515, 587, 636, 873, 993, 995,
            1025, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2222, 3000, 3128,
            3306, 3389, 4000, 4200, 4443, 5000, 5222, 5432, 5672, 5900, 5985, 5986, 6000, 6379,
            6667, 7000, 7077, 8000, 8008, 8080, 8081, 8088, 8443, 8500, 8888, 9000, 9090, 9092,
            9200, 9300, 9418, 9999, 10000, 11211, 27017, 27018, 28017, 50000, 50070
        ]
    },
    "standard": {
        "name": "Privileged Ports (1-1024)",
        "description": "Standard scan of all well-known system ports (1-1024)",
        "ports": list(range(1, 1025))
    },
    "web": {
        "name": "Web & Cloud Services",
        "description": "Web servers, proxies, reverse proxies, and development ports",
        "ports": [80, 81, 443, 2082, 2083, 3000, 4200, 5000, 5173, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443]
    },
    "databases": {
        "name": "Databases & Caches",
        "description": "SQL, NoSQL, in-memory caches, and message brokers",
        "ports": [1433, 1521, 2181, 3306, 5432, 5672, 6379, 9042, 9092, 9200, 9300, 11211, 27017, 27018]
    },
    "remote_admin": {
        "name": "Remote Admin & Infrastructure",
        "description": "SSH, Telnet, RDP, VNC, WinRM, SNMP, IPMI management ports",
        "ports": [22, 23, 135, 139, 445, 623, 1080, 1194, 1723, 2222, 3389, 5900, 5901, 5985, 5986]
    }
}


def resolve_target(target: str) -> Dict[str, Any]:
    """Resolves target hostname to IP and performs PTR reverse lookup & latency probe."""
    target = target.strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if not target:
        raise ValueError("Target cannot be empty.")

    start_time = time.time()
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host '{target}': {e}")

    # Reverse DNS Lookup
    hostname = target
    try:
        rev_name, _, _ = socket.gethostbyaddr(ip)
        if rev_name:
            hostname = rev_name
    except Exception:
        pass

    # Latency estimation via socket connection to port 80/443/53 or test socket
    latency_ms = None
    for test_port in [80, 443, 53, 135, 22]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            p_start = time.time()
            res = s.connect_ex((ip, test_port))
            p_end = time.time()
            s.close()
            if res == 0 or res in [10061, 111]:  # 0 is open, 10061/111 is connection refused (host is alive!)
                latency_ms = round((p_end - p_start) * 1000, 2)
                break
        except Exception:
            continue

    if latency_ms is None:
        latency_ms = round((time.time() - start_time) * 1000, 2)

    return {
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "latency_ms": latency_ms,
        "is_localhost": ip in ["127.0.0.1", "::1", "localhost"] or ip.startswith("127.")
    }


def grab_banner(ip: str, port: int, timeout: float = 0.5) -> str:
    """Attempts banner grabbing or HTTP/TLS identification for open ports."""
    # Check for TLS / HTTPS first if 443/8443
    if port in [443, 8443, 9443]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    return f"TLS: {version} | Cipher: {cipher[0] if cipher else 'Unknown'}"
        except Exception:
            pass

    # Standard TCP banner probe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        # Send HTTP GET for web ports
        if port in [80, 8080, 8000, 3000, 5000, 8888, 9000]:
            probe = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: CyberPortScanner/2.0\r\nConnection: close\r\n\r\n".encode()
            s.sendall(probe)
        else:
            # Generic trigger
            s.sendall(b"\r\n")

        data = s.recv(512)
        s.close()
        if data:
            raw = data.decode("utf-8", errors="ignore").strip()
            lines = [line.strip() for line in raw.split("\n") if line.strip()]
            if lines:
                for l in lines:
                    if l.lower().startswith("server:"):
                        return l
                return lines[0][:120]
    except Exception:
        pass

    return ""


def scan_single_port(ip: str, port: int, timeout: float = 0.2, grab_banners: bool = True) -> Dict[str, Any]:
    """Scans an individual port on the target IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    start_time = time.time()
    result_code = sock.connect_ex((ip, port))
    resp_time_ms = round((time.time() - start_time) * 1000, 2)
    sock.close()

    is_open = (result_code == 0)
    service_info = PORT_DATABASE.get(port, {})
    service_name = service_info.get("service")

    if not service_name:
        try:
            service_name = socket.getservbyport(port, "tcp").upper()
        except (OSError, socket.error):
            service_name = "UNKNOWN"

    risk_level = service_info.get("risk", "Low")
    desc = service_info.get("desc", f"Standard port {port} service")
    banner = ""

    if is_open and grab_banners:
        banner = grab_banner(ip, port, timeout=min(timeout * 2, 0.6))

    return {
        "port": port,
        "state": "OPEN" if is_open else "CLOSED",
        "service": service_name,
        "protocol": service_info.get("proto", "TCP"),
        "risk": risk_level if is_open else "Info",
        "description": desc,
        "response_time_ms": resp_time_ms,
        "banner": banner,
        "result_code": result_code
    }


class PortScannerEngine:
    """Multi-threaded high-performance port scanner engine with streaming progress callbacks."""

    def __init__(self, target: str, ports: List[int], max_workers: int = 50, timeout: float = 0.25):
        self.target = target
        self.ports = ports
        self.max_workers = max(1, min(max_workers, 300))
        self.timeout = max(0.05, min(timeout, 2.0))
        self._is_cancelled = False
        self.target_info: Optional[Dict[str, Any]] = None
        self.results: List[Dict[str, Any]] = []
        self.open_ports: List[Dict[str, Any]] = []
        self.start_time: float = 0
        self.end_time: float = 0

    def cancel(self):
        self._is_cancelled = True

    def run(self, progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Runs the multi-threaded scan and streams progress."""
        self.target_info = resolve_target(self.target)
        ip = self.target_info["ip"]
        total_ports = len(self.ports)

        self.start_time = time.time()
        scanned_count = 0

        # Emit scan start event
        if progress_callback:
            progress_callback({
                "type": "scan_start",
                "target_info": self.target_info,
                "total_ports": total_ports,
                "max_workers": self.max_workers,
                "timeout": self.timeout,
                "timestamp": datetime.now().isoformat()
            })

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(scan_single_port, ip, p, self.timeout): p
                for p in self.ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                if self._is_cancelled:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                port = future_to_port[future]
                try:
                    res = future.result()
                except Exception as e:
                    res = {
                        "port": port,
                        "state": "ERROR",
                        "service": "UNKNOWN",
                        "protocol": "TCP",
                        "risk": "Info",
                        "description": str(e),
                        "response_time_ms": 0,
                        "banner": "",
                        "result_code": -1
                    }

                scanned_count += 1
                self.results.append(res)
                if res["state"] == "OPEN":
                    self.open_ports.append(res)

                if progress_callback:
                    elapsed = time.time() - self.start_time
                    speed = round(scanned_count / max(elapsed, 0.001), 1)
                    progress_callback({
                        "type": "port_scanned",
                        "port_data": res,
                        "scanned_count": scanned_count,
                        "total_ports": total_ports,
                        "percent": round((scanned_count / total_ports) * 100, 1),
                        "open_count": len(self.open_ports),
                        "speed": speed,
                        "elapsed_seconds": round(elapsed, 2)
                    })

        self.end_time = time.time()
        duration = round(self.end_time - self.start_time, 2)

        summary = {
            "type": "scan_complete",
            "target_info": self.target_info,
            "total_ports": total_ports,
            "scanned_ports": scanned_count,
            "open_count": len(self.open_ports),
            "open_ports": sorted(self.open_ports, key=lambda x: x["port"]),
            "duration_seconds": duration,
            "speed_ports_sec": round(scanned_count / max(duration, 0.001), 1),
            "is_cancelled": self._is_cancelled,
            "timestamp": datetime.now().isoformat()
        }

        if progress_callback:
            progress_callback(summary)

        return summary
