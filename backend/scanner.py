from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import nmap


class NmapNotInstalledError(RuntimeError):
    """Raised when the nmap binary is missing."""


class HostUnreachableError(RuntimeError):
    """Raised when the target host can't be scanned/reached."""


@dataclass(frozen=True)
class ScanResult:
    target_ip: str
    scan_time_iso: str
    open_ports: list[int]
    services: list[dict]


def run_nmap_version_scan(
    *,
    target_ip: str,
    port_range: str = "1-1024",
    timing: str = "-T3",
    host_timeout: str = "30s",
    version_detection: str = "--version-light",
) -> ScanResult:
    """
    Real port scan using python-nmap (invokes local nmap safely).
    No raw subprocess / shell execution with user input.
    """
    try:
        scanner = nmap.PortScanner()
    except (nmap.PortScannerError, FileNotFoundError) as e:
        raise NmapNotInstalledError("Nmap is not installed or not in PATH.") from e

    # Safe, non-exploitative scan:
    # -Pn: skip host discovery ping (works on restricted ICMP envs)
    # -sV: service/version detection (lightweight)
    # no NSE scripts, no vuln checks, no brute-force.
    args = f"-Pn {timing} -sV {version_detection} --host-timeout {host_timeout}"

    try:
        scanner.scan(hosts=target_ip, ports=port_range, arguments=args)
    except nmap.PortScannerError as e:
        # PortScannerError is used for a bunch of underlying nmap failures.
        raise HostUnreachableError(str(e)) from e

    now_iso = datetime.now(timezone.utc).isoformat()
    open_ports: list[int] = []
    services: list[dict] = []

    if target_ip not in scanner.all_hosts():
        # If nmap produced no host entry, treat as unreachable/blocked.
        raise HostUnreachableError("Host unreachable or no response from scan.")

    host_info = scanner[target_ip]
    tcp_info = host_info.get("tcp", {}) if isinstance(host_info, dict) else {}

    for port, pdata in sorted(tcp_info.items(), key=lambda x: x[0]):
        if not isinstance(pdata, dict):
            continue
        if pdata.get("state") != "open":
            continue

        open_ports.append(int(port))
        product = (pdata.get("product") or "").strip()
        version = (pdata.get("version") or "").strip()
        extrainfo = (pdata.get("extrainfo") or "").strip()
        name = (pdata.get("name") or "").strip()

        version_str = " ".join([p for p in [product, version, extrainfo] if p]).strip()

        services.append(
            {
                "port": int(port),
                "service": name or "unknown",
                "version": version_str,
            }
        )

    return ScanResult(
        target_ip=target_ip,
        scan_time_iso=now_iso,
        open_ports=open_ports,
        services=services,
    )

