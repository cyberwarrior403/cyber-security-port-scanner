from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MappedFinding:
    severity: str
    possible_attack: str
    recommendation: str


# Rule-based, educational mapping only (no exploitation).
# Keys are ports; can be extended in one place.
PORT_RULES: dict[int, MappedFinding] = {
    21: MappedFinding(
        severity="high",
        possible_attack="FTP: Anonymous login misuse / credential brute force (theoretical)",
        recommendation="Disable anonymous FTP, enforce strong credentials, prefer SFTP/FTPS, and restrict access by IP.",
    ),
    22: MappedFinding(
        severity="medium",
        possible_attack="SSH: Brute force risk if password auth enabled (theoretical)",
        recommendation="Disable password auth (use keys), enforce MFA where possible, rate-limit, and restrict by IP.",
    ),
    80: MappedFinding(
        severity="medium",
        possible_attack="HTTP: Web app risks like XSS / SQL Injection (theoretical)",
        recommendation="Harden HTTP headers, keep frameworks patched, validate inputs server-side, and run secure code reviews.",
    ),
    443: MappedFinding(
        severity="low",
        possible_attack="HTTPS: SSL/TLS misconfiguration (theoretical)",
        recommendation="Use modern TLS, disable legacy ciphers/protocols, enable HSTS, and keep certificates properly managed.",
    ),
    3306: MappedFinding(
        severity="high",
        possible_attack="MySQL: Weak credentials / exposed admin access (theoretical)",
        recommendation="Bind to localhost/private networks, enforce strong auth, least privilege, and restrict firewall rules.",
    ),
}


def map_port_to_finding(port: int, service_name: str) -> MappedFinding:
    # Prefer explicit port mapping; otherwise use a conservative default.
    if port in PORT_RULES:
        return PORT_RULES[port]

    # Service-based fallback (very conservative).
    s = (service_name or "").lower()
    if s in {"ftp", "ftps"}:
        return PORT_RULES[21]
    if s == "ssh":
        return PORT_RULES[22]
    if s in {"http", "http-proxy"}:
        return PORT_RULES[80]
    if s in {"https", "ssl", "tls"}:
        return PORT_RULES[443]
    if s in {"mysql", "mariadb"}:
        return PORT_RULES[3306]

    return MappedFinding(
        severity="low",
        possible_attack="Unknown service: potential misconfiguration or outdated software (theoretical)",
        recommendation="Confirm service necessity, patch regularly, and restrict exposure with firewall rules.",
    )

