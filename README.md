# nulrix-portscanner
Fast, lightweight **TCP port scanner** built with `asyncio`. No raw packets, no admin/root required — perfect for **ethical hacking**, **CTFs**, and learning.

> Created by **Nulrix**. Projects for education & authorized testing only.

## Features
- Async TCP **connect** scan (portable, user-mode)
- Port spec: single, list, ranges (`1-1024,80,443,8080-8090`)
- **Concurrency** & **timeout** controls
- Optional **banner grab** (best-effort; minimal protocol probes for HTTP/Redis/etc.)
- **JSON** output for scripting/automation
- Clean, colored CLI output

## Quick Start
```bash
python3 scanner.py -H example.com
```

Scan a range + common ports and grab banners:
```bash
python3 scanner.py -H 192.168.1.10 -p 1-1024,3306,5432,6379 -b -c 400 -t 1.0 -o report.json
```

## Arguments
```
-H, --host         Target host or IP (required)
-p, --ports        Ports to scan. Default: curated common ports (≈100)
-c, --concurrency  Max concurrent connections (default: 200)
-t, --timeout      Per-connection timeout in seconds (default: 1.5)
-b, --banner       Attempt banner grabbing on open ports
-o, --out          Write JSON report to a file
```

## JSON Output Example
```json
{
  "target": "example.com",
  "resolved_ip": "93.184.216.34",
  "elapsed_ms": 512,
  "open_ports": [{"port": 80, "service": "http", "state": "open", "banner": "HTTP/1.1 200 OK ..."}]
}
```

## Notes
- **Accuracy**: TCP connect scanning may miss ports protected by strict rate-limiting or firewall rules. Re-scan with different timeouts if needed.
- **Banner grabbing** is best-effort; many services suppress banners by default.
- **Legality**: Only scan hosts you **own** or have **explicit permission** to test.

## Ethics
> **For education & authorized testing only.**  
Misuse may violate laws and policies. You are responsible for your actions.

## 📦 Requirements
- Python 3.9+ (standard library only; no external deps)

## 📝 License
MIT © 2025 Nulrix
