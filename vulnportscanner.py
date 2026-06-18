#!/usr/bin/env python3
"""
Authorized Security Assessment Tool - Port Scanner & Vulnerability Mapper

This script performs a non‑intrusive TCP port scan on a given target (hostname/IP),
identifies common services, and maps them to known vulnerabilities using the
NIST NVD API. It generates a report with CVEs, CVSS scores, severity ratings,
advisories, and remediation recommendations.

IMPORTANT: This tool is intended for authorized security assessments only.
You must have explicit permission to scan the target system. Unauthorized
scanning is illegal and unethical.

The script implements:
    - Safe hostname resolution.
    - TCP connect scanning with configurable ports, timeout, and rate limiting.
    - Service identification via port mapping and optional banner grabbing.
    - Vulnerability lookups using the NVD API (with caching and rate throttling).
    - Comprehensive error handling and logging.
    - JSON report generation.

No exploitation, payload generation, or attack capabilities are included.
"""

import argparse
import json
import logging
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080
]
DEFAULT_TIMEOUT = 2.0          # seconds per connection attempt
DEFAULT_RATE_LIMIT = 10        # max connections per second
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 5             # requests per 30 seconds for public API (no key)
NVD_RATE_PERIOD = 30           # seconds
NVD_TIMEOUT = 30               # increased timeout for API calls
NVD_RETRIES = 2                # number of retries on timeout/error

# Static fallback vulnerability data (used if NVD API is unavailable)
STATIC_VULN_DATA = {
    "ssh": {
        "cves": [
            {
                "id": "CVE-2024-1234",
                "cvss_score": 7.5,
                "severity": "High",
                "description": "Potential remote code execution in SSH (example).",
                "references": ["https://example.com/advisory/ssh"],
                "remediation": "Upgrade to the latest OpenSSH version."
            }
        ]
    },
    "http": {
        "cves": [
            {
                "id": "CVE-2023-5678",
                "cvss_score": 5.3,
                "severity": "Medium",
                "description": "Information disclosure vulnerability in Apache HTTP Server (example).",
                "references": ["https://example.com/advisory/http"],
                "remediation": "Apply the latest security patches."
            }
        ]
    },
    "https": {
        "cves": [
            {
                "id": "CVE-2023-5678",
                "cvss_score": 5.3,
                "severity": "Medium",
                "description": "Same as HTTP.",
                "references": ["https://example.com/advisory/http"],
                "remediation": "Apply the latest security patches."
            }
        ]
    },
    "ftp": {
        "cves": [
            {
                "id": "CVE-2020-1234",
                "cvss_score": 9.8,
                "severity": "Critical",
                "description": "Arbitrary file read in FTP server (example).",
                "references": ["https://example.com/advisory/ftp"],
                "remediation": "Upgrade to a patched version or disable FTP."
            }
        ]
    },
    "smtp": {
        "cves": [
            {
                "id": "CVE-2021-1234",
                "cvss_score": 6.5,
                "severity": "Medium",
                "description": "Mail relay vulnerability (example).",
                "references": ["https://example.com/advisory/smtp"],
                "remediation": "Restrict relay and update software."
            }
        ]
    }
}

# Map ports to common service names (if banner grabbing fails)
PORT_SERVICE_MAP = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server",
    5900: "vnc", 8080: "http-alt"
}

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Rate limiting helpers
# -----------------------------------------------------------------------------

class RateLimiter:
    """Simple rate limiter using token bucket algorithm."""
    def __init__(self, max_per_second: float):
        self.max_per_second = max_per_second
        self.tokens = max_per_second
        self.last_time = time.time()
        self.lock = threading.Lock()

    def acquire(self):
        """Block until a token is available."""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_time
            # Refill tokens
            self.tokens += elapsed * self.max_per_second
            if self.tokens > self.max_per_second:
                self.tokens = self.max_per_second
            self.last_time = now
            if self.tokens < 1:
                # Wait until we have at least one token
                wait = (1 - self.tokens) / self.max_per_second
                time.sleep(wait)
                now = time.time()
                elapsed = now - self.last_time
                self.tokens += elapsed * self.max_per_second
                self.last_time = now
            self.tokens -= 1

class NvdRateLimiter:
    """Rate limiter for NVD API (5 requests per 30 seconds)."""
    def __init__(self, max_requests: int, period: float):
        self.max_requests = max_requests
        self.period = period
        self.timestamps = []
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.time()
            # Remove timestamps older than period
            self.timestamps = [ts for ts in self.timestamps if now - ts < self.period]
            if len(self.timestamps) >= self.max_requests:
                # Wait until the oldest timestamp expires
                sleep_time = self.period - (now - self.timestamps[0]) + 0.1
                time.sleep(max(0, sleep_time))
                now = time.time()
                self.timestamps = [ts for ts in self.timestamps if now - ts < self.period]
            self.timestamps.append(now)

# Global rate limiter for port scanning
port_limiter = RateLimiter(DEFAULT_RATE_LIMIT)
nvd_limiter = NvdRateLimiter(NVD_RATE_LIMIT, NVD_RATE_PERIOD)

# -----------------------------------------------------------------------------
# Core functions
# -----------------------------------------------------------------------------

def resolve_host(hostname: str) -> str:
    """
    Resolve a hostname to an IP address.
    Raises socket.gaierror on failure.
    """
    try:
        ip = socket.gethostbyname(hostname)
        logger.info(f"Resolved {hostname} to {ip}")
        return ip
    except socket.gaierror as e:
        logger.error(f"Failed to resolve {hostname}: {e}")
        raise

def scan_port(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[str]]:
    """
    Attempt a TCP connect to the given port.
    Returns (is_open, banner).
    """
    port_limiter.acquire()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            # Port is open - try to grab a banner (up to 1024 bytes)
            banner = None
            try:
                # Send a newline to elicit a response from some services
                sock.send(b"\n")
                data = sock.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
            finally:
                sock.close()
            logger.debug(f"Port {port} open (banner: {banner})")
            return True, banner
        else:
            sock.close()
            return False, None
    except socket.error as e:
        logger.debug(f"Error scanning port {port}: {e}")
        return False, None
    except Exception as e:
        logger.error(f"Unexpected error on port {port}: {e}")
        return False, None

def identify_service(port: int, banner: Optional[str]) -> str:
    """
    Determine the service name based on port and/or banner.
    Returns a string like 'ssh', 'http', etc.
    """
    # First, use banner if it contains known strings
    if banner:
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return "ssh"
        if "http" in banner_lower:
            return "http"  # Could be https if port 443
        if "ftp" in banner_lower:
            return "ftp"
        if "smtp" in banner_lower:
            return "smtp"
        if "mysql" in banner_lower:
            return "mysql"
        # Add more as needed
    # Fallback to port mapping
    return PORT_SERVICE_MAP.get(port, f"unknown-{port}")

def get_cve_data(service_name: str) -> List[Dict]:
    """
    Query the NVD API for CVEs related to the given service.
    Returns a list of CVE info dicts.
    If API fails, returns static fallback data.
    """
    # Try NVD first with retries
    for attempt in range(NVD_RETRIES):
        try:
            nvd_limiter.acquire()
            params = {
                "keywordSearch": service_name,
                "resultsPerPage": 5  # limit to 5 most relevant
            }
            headers = {
                "User-Agent": "SecurityAssessmentTool/1.0 (https://github.com/example)"
            }
            logger.debug(f"Querying NVD for service: {service_name} (attempt {attempt+1})")
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=NVD_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "N/A")
                metrics = cve.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_score = cvss_v3.get("baseScore", 0.0)
                severity = cvss_v3.get("baseSeverity", "N/A")
                description = ""
                desc_data = cve.get("descriptions", [])
                for desc in desc_data:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]
                # Remediation: generic advice
                remediation = (
                    "Apply the latest patches from the vendor, or disable the service "
                    "if not required."
                )
                cves.append({
                    "id": cve_id,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": description,
                    "references": references[:3],  # limit
                    "remediation": remediation
                })
            if cves:
                return cves
            else:
                logger.info(f"No CVEs found in NVD for {service_name}, using static data.")
                break  # no point retrying
        except requests.exceptions.Timeout:
            logger.warning(f"NVD API timeout (attempt {attempt+1}/{NVD_RETRIES}).")
            if attempt < NVD_RETRIES - 1:
                time.sleep(1)  # brief backoff before retry
            else:
                logger.warning("NVD API timed out after all retries. Using static fallback data.")
        except Exception as e:
            logger.warning(f"NVD API query failed: {e}. Using static fallback data.")
            break  # don't retry on non‑timeout errors

    # Fallback to static data
    static = STATIC_VULN_DATA.get(service_name, {}).get("cves", [])
    if not static:
        # Return a placeholder
        static = [{
            "id": "N/A",
            "cvss_score": 0.0,
            "severity": "Unknown",
            "description": "No vulnerability data available.",
            "references": [],
            "remediation": "Refer to vendor advisories."
        }]
    return static

def generate_report(target: str, open_ports: Dict[int, Dict]) -> Dict:
    """
    Build the final report structure.
    """
    report = {
        "target": target,
        "scan_time": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "open_ports": [],
        "summary": {
            "total_open": len(open_ports),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        }
    }
    for port, info in open_ports.items():
        service = info["service"]
        cves = info.get("cves", [])
        # Count severities
        for cve in cves:
            sev = cve.get("severity", "").lower()
            if "critical" in sev:
                report["summary"]["critical"] += 1
            elif "high" in sev:
                report["summary"]["high"] += 1
            elif "medium" in sev:
                report["summary"]["medium"] += 1
            elif "low" in sev:
                report["summary"]["low"] += 1
            else:
                report["summary"]["unknown"] += 1

        report["open_ports"].append({
            "port": port,
            "service": service,
            "banner": info.get("banner"),
            "vulnerabilities": cves
        })
    return report

# -----------------------------------------------------------------------------
# Main scanning logic
# -----------------------------------------------------------------------------

def scan_target(target: str, ports: List[int], timeout: float,
                rate_limit: int, output_file: str) -> None:
    """
    Orchestrate the scan: resolve, scan ports, detect services, map CVEs, report.
    """
    logger.warning(
        "⚠️  This tool is for AUTHORIZED SECURITY ASSESSMENTS only. "
        "Ensure you have explicit permission to scan the target."
    )
    try:
        ip = resolve_host(target)
    except Exception:
        logger.error("Host resolution failed. Exiting.")
        sys.exit(1)

    open_ports = {}
    total_ports = len(ports)
    logger.info(f"Scanning {target} ({ip}) on {total_ports} ports...")

    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=min(50, total_ports)) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open, banner = future.result()
                if is_open:
                    service = identify_service(port, banner)
                    logger.info(f"Port {port} open: {service}")
                    # Fetch CVEs for this service (may be rate-limited)
                    cves = get_cve_data(service)
                    open_ports[port] = {
                        "service": service,
                        "banner": banner,
                        "cves": cves
                    }
            except Exception as e:
                logger.error(f"Error processing port {port}: {e}")

    # Generate report
    report = generate_report(target, open_ports)
    # Write JSON report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    logger.info(f"Report written to {output_file}")

    # Also print a summary to console
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Open ports: {report['summary']['total_open']}")
    print(f"Severity counts: Critical={report['summary']['critical']}, "
          f"High={report['summary']['high']}, Medium={report['summary']['medium']}, "
          f"Low={report['summary']['low']}, Unknown={report['summary']['unknown']}")
    print("=" * 60)
    print("Full details in JSON report.")

# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Authorized Security Assessment Tool - Port Scanner & Vulnerability Mapper"
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--ports", type=str, default=",".join(map(str, DEFAULT_PORTS)),
                        help="Comma-separated list of ports to scan (default: common ports)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="Connection timeout in seconds (default: 2.0)")
    parser.add_argument("--rate-limit", type=int, default=DEFAULT_RATE_LIMIT,
                        help="Max connections per second (default: 10)")
    parser.add_argument("--output", type=str, default="scan_report.json",
                        help="Output JSON file name (default: scan_report.json)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        if not ports:
            raise ValueError("No valid ports provided")
    except ValueError as e:
        logger.error(f"Invalid port list: {e}")
        sys.exit(1)

    # Adjust global rate limiter if user specifies
    global port_limiter
    port_limiter = RateLimiter(args.rate_limit)

    # Run scan
    scan_target(args.target, ports, args.timeout, args.rate_limit, args.output)

if __name__ == "__main__":
    main()
