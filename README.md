# VulnPortScanner
Non‑intrusive TCP port scanner with vulnerability mapping via NVD API. Generates JSON reports with CVEs, CVSS scores, and remediation. Authorised use only.
# VulnPortScanner

**Authorised Security Assessment Tool – Port Scanner & Vulnerability Mapper**

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ⚠️ Important Legal Notice

**This tool is designed for authorised security assessments only.**  
You must have **explicit, written permission** from the owner of the target system before running any scan. Unauthorised scanning is illegal in many jurisdictions and may be considered a cyber‑attack. The author assumes no liability for misuse.

---

## 🔍 Overview

VulnPortScanner is a lightweight, non‑intrusive TCP port scanner that:
- Resolves hostnames to IP addresses.
- Scans a configurable list of ports (with rate limiting).
- Identifies services via banner grabbing and port‑to‑service mapping.
- Queries the **NIST NVD API** to retrieve known CVEs and CVSS scores for each detected service.
- Generates a structured JSON report with vulnerability details, severity ratings, and remediation advice.

No exploitation, payload generation, or attack capabilities are included – it only collects information.

---

## ✨ Features

- **Safe & non‑intrusive** – uses TCP connect scans only.
- **Rate‑limited** – prevents flooding the target (configurable).
- **Concurrent** – fast scanning with thread pooling.
- **Service detection** – identifies common services (SSH, HTTP, FTP, etc.) via port and banner.
- **Vulnerability mapping** – fetches real‑time CVE data from the NVD API (with retries and timeout handling).
- **Fallback data** – if the API fails, static example data is used to demonstrate the report format.
- **JSON output** – machine‑readable reports for integration with other tools.
- **Detailed logging** – configurable verbosity for debugging.

---

## 📦 Installation

### Requirements
- Python 3.6 or higher
- `requests` library

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/VulnPortScanner.git
   cd VulnPortScanner
   ```

2. Install the required Python package:
   ```bash
   pip install requests
   ```
   *(If you’re on a system that blocks global pip installs, use a virtual environment or install via your system package manager – e.g., `sudo apt install python3-requests` on Debian/Kali.)*

---

## 🚀 Usage

```bash
python vulnportscanner.py <target> [options]
```

### Basic Example
```bash
python vulnportscanner.py example.com
```

This scans the default port list (common services) on `example.com`.

### Scan Specific Ports
```bash
python vulnportscanner.py example.com --ports 22,80,443
```

### Adjust Timeout & Rate Limit
```bash
python vulnportscanner.py example.com --timeout 3.0 --rate-limit 5
```

### Save Report to a Custom File
```bash
python vulnportscanner.py example.com --output my_scan.json
```

### Enable Debug Logging
```bash
python vulnportscanner.py example.com --debug
```

---

## ⚙️ Command‑Line Options

| Option | Description |
|--------|-------------|
| `target` | Hostname or IP address to scan (required). |
| `--ports` | Comma‑separated list of ports (default: common ports). |
| `--timeout` | Connection timeout per port in seconds (default: 2.0). |
| `--rate-limit` | Maximum connection attempts per second (default: 10). |
| `--output` | Output JSON filename (default: `scan_report.json`). |
| `--debug` | Enable debug logging. |

---

## 📄 Output Report

The tool generates a JSON file with the following structure:

```json
{
  "target": "example.com",
  "scan_time": "2026-06-18T10:30:00Z",
  "open_ports": [
    {
      "port": 22,
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_8.9p1",
      "vulnerabilities": [
        {
          "id": "CVE-2024-1234",
          "cvss_score": 7.5,
          "severity": "High",
          "description": "Potential remote code execution in SSH.",
          "references": ["https://example.com/advisory/ssh"],
          "remediation": "Upgrade to the latest OpenSSH version."
        }
      ]
    }
  ],
  "summary": {
    "total_open": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "unknown": 0
  }
}
```

- **`vulnerabilities`** – List of CVEs with CVSS scores, severity, descriptions, references, and recommended remediation.
- **`summary`** – Aggregated severity counts across all open ports.

---

## 🔧 Configuration (for advanced users)

You can adjust the following constants at the top of the script:

- `DEFAULT_PORTS` – the default port list.
- `DEFAULT_TIMEOUT` – connection timeout.
- `DEFAULT_RATE_LIMIT` – ports per second.
- `NVD_TIMEOUT` – API request timeout (default 30s).
- `NVD_RETRIES` – number of retries on API failure.

If you have an **NVD API key**, you can add it to the request parameters to increase your rate limit. (Not included by default to keep the tool simple.)

---

## 🐛 Limitations

- The NVD API is rate‑limited (5 requests per 30 seconds for public users). The script respects this limit but may still be throttled.
- Service identification is basic – it relies on port numbers and simple banner strings. It does not perform deep protocol fingerprinting.
- The static fallback data are **examples only** – they are not real CVEs. Real data are fetched from the NVD API when available.
- The script does not scan UDP ports.

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests for:

- Better service fingerprinting.
- Additional vulnerability databases (e.g., Exploit-DB).
- Enhanced reporting (HTML, PDF).
- Improved error handling and performance.

Please ensure that any new features maintain the **non‑exploitative** nature of the tool.

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 📬 Disclaimer

**The author is not responsible for any misuse of this tool.** By using this software, you agree that you have the proper authorisation to scan the target system and that you will not use it for illegal or unethical purposes. Always follow your organisation’s security policies and applicable laws.

---

**Happy (Authorised) Scanning!** 🛡️
