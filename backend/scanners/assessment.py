"""Shared interpretation of collection outcomes, separate from security findings."""


def collection_checks(results):
    checks = []
    for key, label in [("whois", "WHOIS"), ("dns", "DNS"), ("ssl", "TLS"), ("headers", "HTTP headers"), ("tech", "Technologies")]:
        value = results.get("technologies" if key == "tech" else key)
        status, reason = "inconclusive", "No usable evidence returned."
        tech_error = next((v for v in value if isinstance(v, str) and v.lower().startswith("error:")), None) if key == "tech" and isinstance(value, list) else None
        error = value.get("error") if isinstance(value, dict) else None
        if error or tech_error:
            status = "completed" if isinstance(value, dict) and value.get("certificate_error") else "failed"
            reason = str(error or tech_error)
        elif key == "whois" and isinstance(value, dict) and any(v for k, v in value.items() if k not in ("domain_name", "error")):
            status, reason = "completed", "Registration data received."
        elif key == "dns" and isinstance(value, dict) and any(isinstance(v, list) and v for v in value.values()):
            status, reason = "completed", "DNS records received."
        elif key == "ssl" and isinstance(value, dict) and value.get("valid") is True:
            status, reason = "completed", "Certificate validated for this connection."
        elif key == "headers" and isinstance(value, dict) and isinstance(value.get("status_code"), int):
            status, reason = "completed", f"HTTP {value['status_code']}; headers inspected."
        elif key == "tech" and isinstance(value, list) and value:
            status, reason = "completed", "Heuristic matches found; review evidence."
        checks.append({"key": key, "label": label, "status": status, "reason": reason})
    return checks


def collection_status(checks):
    if all(c["status"] == "completed" for c in checks):
        return "completed"
    if all(c["status"] == "failed" for c in checks):
        return "failed"
    return "partial"
