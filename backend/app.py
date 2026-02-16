from __future__ import annotations

from flask import Flask, jsonify, request
from flask_cors import CORS

from backend.config import get_settings
from backend.risk import compute_risk
from backend.scanner import HostUnreachableError, NmapNotInstalledError, run_nmap_version_scan
from backend.validation import DNSResolutionError, InvalidTargetError, validate_and_resolve_target
from backend.vuln_mapping import map_port_to_finding


def create_app() -> Flask:
    settings = get_settings()

    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": settings.CORS_ORIGINS}})

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/api/scan")
    def scan():
        """
        Secure scan endpoint:
        - Strictly validate + normalize input
        - Resolve domain to IPv4 using DNS
        - Scan ONLY the resolved IPv4 (never scan raw user input)
        - No exploitation; only educational suggestions
        """
        payload = request.get_json(silent=True) or {}
        user_target = payload.get("target")

        try:
            validated = validate_and_resolve_target(user_target)
        except InvalidTargetError:
            return jsonify({"error": "Invalid IP address or domain name."}), 400
        except DNSResolutionError:
            return jsonify({"error": "DNS resolution failed."}), 400

        # Optional policy: allowlist demo hosts (original project requirement).
        # Disable by setting ENFORCE_ALLOWLIST=0.
        if settings.ENFORCE_ALLOWLIST and settings.ALLOWED_HOSTNAMES:
            if (
                not validated.is_ip
                and validated.normalized_target not in settings.ALLOWED_HOSTNAMES
            ):
                return (
                    jsonify(
                        {
                            "error": "Target not allowed. Only approved demo targets can be scanned.",
                            "allowed_targets": sorted(settings.ALLOWED_HOSTNAMES),
                        }
                    ),
                    403,
                )

        try:
            scan_res = run_nmap_version_scan(
                target_ip=validated.resolved_ip,
                port_range=settings.DEFAULT_PORT_RANGE,
                timing=settings.NMAP_TIMING,
                host_timeout=settings.HOST_TIMEOUT,
                version_detection=settings.VERSION_DETECTION,
            )
        except NmapNotInstalledError:
            return jsonify({"error": "Nmap not installed."}), 500
        except HostUnreachableError:
            return jsonify({"error": "Host unreachable."}), 504

        enriched_services: list[dict] = []
        for svc in scan_res.services:
            port = int(svc["port"])
            service_name = str(svc.get("service") or "")
            finding = map_port_to_finding(port, service_name)
            enriched_services.append(
                {
                    "port": port,
                    "service": service_name,
                    "version": str(svc.get("version") or ""),
                    "severity": finding.severity,
                    "possible_attack": finding.possible_attack,
                    "recommendation": finding.recommendation,
                }
            )

        total_points, percent, risk_level, summary = compute_risk(enriched_services)

        response = {
            "disclaimer": settings.ETHICAL_DISCLAIMER,
            "target": validated.normalized_target,
            "resolved_ip": validated.resolved_ip,
            "scan_time": scan_res.scan_time_iso,
            "open_ports": scan_res.open_ports,
            "services": enriched_services,
            "risk_score": {"points": total_points, "percent": percent},
            "risk_level": risk_level,
            "summary": {
                "critical": summary.critical,
                "high": summary.high,
                "medium": summary.medium,
                "low": summary.low,
            },
        }
        return jsonify(response)

    return app


if __name__ == "__main__":
    # Dev-only entry point
    create_app().run(host="127.0.0.1", port=5000, debug=True)

