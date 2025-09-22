#!/usr/bin/env python3 
"""    
Nulrix Port Scanner 
Lightweight, fast TCP port scanner for ethical hacking & CTF practice.

Features
- Async TCP connect scan (no raw packets, no admin required)
- Port specification: single, comma list, ranges (e.g., 1-1024,80,443,8080-8090)
- Concurrency control and timeouts
- Optional banner grab (best-effort) including minimal HTTP probe
- JSON output option
- Clean, colored CLI output

Author: Nulrix
License: MIT
"""
import asyncio
import argparse
import ipaddress
import json
import socket
import sys
import time
from dataclasses import dataclass, asdict
from typing import List, Tuple, Optional

# ---------------------- Utility: colors ----------------------
class C:
    R = "\033[31m"
    G = "\033[32m"
    Y = "\033[33m"
    B = "\033[34m"
    M = "\033[35m"
    C = "\033[36m"
    W = "\033[97m"
    D = "\033[0m"

def color(s, c):  
    return f"{c}{s}{C.D}"

# ---------------------- Common Ports ----------------------
# Short, curated set of common ports for default scans
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 389, 427, 443, 445, 465, 500, 514, 515, 520, 587, 593, 636, 873,
    902, 989, 990, 993, 995, 1025, 1080, 1433, 1434, 1521, 1723, 1883, 2049, 2083,
    2181, 2375, 2376, 2483, 2484, 2628, 3000, 3306, 3389, 3632, 3690, 4369, 5000,
    5044, 5432, 5601, 5666, 5900, 5985, 5986, 6000, 6379, 6443, 6667, 7001, 7002,
    7181, 7199, 7443, 7777, 8000, 8008, 8010, 8080, 8081, 8088, 8161, 8443, 8500,
    8530, 8531, 8834, 8888, 9000, 9042, 9090, 9200, 9300, 9418, 9443, 9527, 9999,
    10000, 11211, 15672, 27017, 27018, 27019, 50070, 50075
]

# ---------------------- Data Models ----------------------
@dataclass
class Result:
    port: int
    service: Optional[str]
    state: str
    banner: Optional[str] = None

@dataclass
class ScanReport:
    target: str
    resolved_ip: str
    elapsed_ms: int
    open_ports: List[Result]

# ---------------------- Parsing ----------------------
def parse_ports(spec: Optional[str]) -> List[int]:
    if not spec:
        return sorted(set(COMMON_PORTS))
    ports = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            for p in range(a, b + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

# ---------------------- Banner Grab ----------------------
async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, timeout: float) -> str:
    try:
        # Try to read immediately (protocols that speak first: FTP, SMTP, POP3, etc.)
        data = await asyncio.wait_for(reader.read(256), timeout=timeout/2)
        if data:
            return data.decode(errors='ignore').strip()

        # Minimal protocol-aware probe
        probe = None
        if port in (80, 8080, 8000, 8008, 8010, 8443, 8888, 9000, 9090, 9200, 9300, 9443):
            probe = b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: nulrix-scan\r\n\r\n"
        elif port in (21, 22, 23, 25, 110, 143, 389, 443, 465, 587, 993, 995):
            probe = b"\r\n"
        elif port in (6379,):
            probe = b"PING\r\n"

        if probe:
            writer.write(probe)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout/2)
            if data:
                return data.decode(errors='ignore').strip()
    except Exception:
        return ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return ""

# ---------------------- Scanner ----------------------
async def scan_port(host: str, port: int, timeout: float, do_banner: bool) -> Optional[Result]:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        service = None
        try:
            service = socket.getservbyport(port)
        except Exception:
            service = None

        banner = None
        if do_banner:
            banner = await grab_banner(reader, writer, port, timeout)
        else:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        return Result(port=port, service=service, state="open", banner=banner or None)
    except Exception:
        return None

async def worker(host: str, queue: asyncio.Queue, timeout: float, do_banner: bool, results: List[Result]):
    while True:
        port = await queue.get()
        if port is None:
            queue.task_done()
            break
        res = await scan_port(host, port, timeout, do_banner)
        if res:
            results.append(res)
            svc = f" ({res.service})" if res.service else ""
            print(f"{color('[+]', C.G)} {host}:{res.port}{svc} {color('open', C.G)}")
            if res.banner:
                preview = res.banner.replace('\\n', ' ').replace('\\r', ' ')
                if len(preview) > 120:
                    preview = preview[:117] + '...'
                print(f"    {color('banner:', C.C)} {preview}")
        queue.task_done()

async def run_scan(target: str, ports: List[int], concurrency: int, timeout: float, banner: bool) -> ScanReport:
    # Resolve hostname
    resolved = socket.gethostbyname(target)
    q: asyncio.Queue = asyncio.Queue()
    for p in ports:
        q.put_nowait(p)
    results: List[Result] = []
    workers = []
    for _ in range(min(concurrency, len(ports)) or 1):
        workers.append(asyncio.create_task(worker(resolved, q, timeout, banner, results)))
    start = time.perf_counter()
    await q.join()
    # Stop workers
    for _ in workers:
        q.put_nowait(None)
    await asyncio.gather(*workers, return_exceptions=True)
    elapsed = int((time.perf_counter() - start) * 1000)
    # Sort by port
    results.sort(key=lambda r: r.port)
    return ScanReport(target=target, resolved_ip=resolved, elapsed_ms=elapsed, open_ports=results)

# ---------------------- CLI ----------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="nulrix-scan",
        description="Nulrix Port Scanner - fast TCP connect scanner (ethical use only)"
    )
    p.add_argument("-H", "--host", required=True, help="Target host or IP")
    p.add_argument("-p", "--ports", default=None, help="Ports to scan, e.g. '1-1024,80,443'. Default: curated common ports")
    p.add_argument("-c", "--concurrency", type=int, default=200, help="Max concurrent connections (default: 200)")
    p.add_argument("-t", "--timeout", type=float, default=1.5, help="Per-connection timeout in seconds (default: 1.5)")
    p.add_argument("-b", "--banner", action="store_true", help="Attempt best-effort banner grabbing on open ports")
    p.add_argument("-o", "--out", default=None, help="Write JSON report to file path")
    return p

def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        ports = parse_ports(args.ports)
        if not ports:
            print(color("No valid ports to scan.", C.Y))
            return 2
        print(color(f"== Nulrix Port Scanner ==", C.M))
        print(f"Target: {args.host} | Ports: {len(ports)} | Concurrency: {args.concurrency} | Timeout: {args.timeout}s | Banner: {args.banner}")
        report = asyncio.run(run_scan(args.host, ports, args.concurrency, args.timeout, args.banner))
        print(color(f"\nScan complete in {report.elapsed_ms} ms. Open ports: {len(report.open_ports)}", C.B))
        if args.out:
            payload = {
                "target": report.target,
                "resolved_ip": report.resolved_ip,
                "elapsed_ms": report.elapsed_ms,
                "open_ports": [asdict(r) for r in report.open_ports],
            }
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(color(f"JSON report saved to {args.out}", C.C))
        return 0
    except socket.gaierror:
        print(color("DNS resolution failed for target host.", C.R))
        return 1
    except KeyboardInterrupt:
        print(color("\nInterrupted.", C.Y))
        return 130

if __name__ == "__main__":
    sys.exit(main())
