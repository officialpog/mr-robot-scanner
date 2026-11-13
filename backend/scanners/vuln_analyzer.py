"""Evidence-based passive findings. Severity is a local policy, not a CVSS score."""
import re

HEADER_REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
TLS_REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"

# Missing controls are hardening observations, not proof of an exploit.
HEADER_RULES = {
    "Content-Security-Policy": ("medium", "A content policy can reduce the impact of injected browser content.", "Develop a CSP for the application's resource needs. Test with Content-Security-Policy-Report-Only before enforcing it."),
    "Strict-Transport-Security": ("medium", "Browsers may attempt an initial unencrypted connection without an HSTS policy.", "After confirming HTTPS works throughout the site, configure an appropriate HSTS max-age. Include subdomains only after verifying they all support HTTPS."),
    "X-Frame-Options": ("low", "Interactive pages may be embedded by another site if no framing policy applies.", "Set an appropriate CSP frame-ancestors directive, or X-Frame-Options DENY/SAMEORIGIN where appropriate. Verify legitimate embedding still works."),
    "X-Content-Type-Options": ("low", "An explicit policy helps prevent browsers from guessing response content types.", "Set X-Content-Type-Options: nosniff and serve resources with correct Content-Type values."),
    "Referrer-Policy": ("low", "An explicit policy makes referrer sharing intentional rather than relying on browser defaults.", "Choose a Referrer-Policy such as strict-origin-when-cross-origin and test outbound links and analytics."),
    "Permissions-Policy": ("info", "Browser feature access has no explicit policy in this response.", "Restrict browser capabilities the application does not need using Permissions-Policy; test features such as camera, microphone, and geolocation."),
}


def analyze_vulnerabilities(target: str, headers_result: dict, ssl_result: dict, tech_list: list):
    findings = []

    def add(rule_id, severity, title, description, solution, evidence, impact,
            category="hardening", confidence="high", reference=HEADER_REFERENCE):
        findings.append({
            "rule_id": rule_id, "severity": severity, "title": title,
            "description": description, "solution": solution, "evidence": evidence,
            "impact": impact, "category": category, "confidence": confidence,
            "verification": "observed" if category != "informational" else "requires_review",
            "affected_target": target, "references": [reference], "cve_id": None,
        })

    if not headers_result.get("error"):
        raw = {k.lower(): v for k, v in headers_result.get("raw", {}).items()}
        csp_directives = {part.strip().split()[0].lower() for part in raw.get("content-security-policy", "").split(";") if part.strip()}
        for header in headers_result.get("missing", []):
            if header not in HEADER_RULES:
                continue
            if header == "X-Frame-Options" and "frame-ancestors" in csp_directives:
                continue
            severity, impact, fix = HEADER_RULES[header]
            add("header.missing." + header.lower(), severity, f"Missing {header}",
                f"The inspected response did not contain {header}. This does not by itself establish an exploitable vulnerability.",
                fix, {"missing_header": header, "status_code": headers_result.get("status_code"), "response_headers": raw}, impact)
        for issue in headers_result.get("hsts_issues", []):
            if "Strict-Transport-Security" in headers_result.get("missing", []):
                continue
            add("header.hsts.configuration", "low", issue, "The observed HSTS policy needs review.",
                HEADER_RULES["Strict-Transport-Security"][2], {"hsts": raw.get("strict-transport-security"), "observation": issue},
                "The intended HTTPS enforcement policy may not apply.")
        for leak in headers_result.get("info_leaks", []):
            name = leak.split(":", 1)[0]
            add("header.banner." + name.lower(), "info", f"Information Disclosure: {name}",
                "The response advertises server technology. A banner is not proof of a vulnerable version.",
                "Remove unnecessary version banners where practical; prioritize patching the underlying software.",
                {"header": leak}, "Technology details can assist reconnaissance.", category="informational")

    if ssl_result.get("weak_ciphers"):
        add("tls.negotiated_weak", "high", "Weak TLS Configuration",
            "This connection negotiated a legacy protocol or a cipher flagged as weak; other supported configurations were not enumerated.",
            "Disable legacy protocols and weak suites, prefer TLS 1.2/1.3, and test required clients after changing the server configuration.",
            ssl_result, "Traffic protection may be weaker than required.", category="weakness", reference=TLS_REFERENCE)
    days = ssl_result.get("expiry_days")
    if isinstance(days, (int, float)) and days < 30:
        expired = days < 0
        add("tls.certificate.expiry", "high" if expired else "medium",
            "SSL Certificate Expired" if expired else "SSL Certificate Expiring Soon",
            f"Certificate expiry is {days} days from the scan time.",
            "Renew the certificate, deploy the correct chain, and verify automated renewal and expiry monitoring.",
            {"expiry_days": days, "not_after": ssl_result.get("not_after")},
            "Expired certificates can prevent clients from establishing trusted connections.", category="weakness", reference=TLS_REFERENCE)
    if ssl_result.get("certificate_error"):
        add("tls.certificate.validation", "high", "Invalid SSL Certificate",
            ssl_result.get("error", "Certificate verification failed."),
            "Check the hostname, validity dates, and certificate chain; install a certificate trusted by the intended clients and retest.",
            ssl_result, "Clients may reject the connection or be unable to authenticate the server.", category="weakness", reference=TLS_REFERENCE)

    tech = [t for t in tech_list if isinstance(t, str) and not t.lower().startswith("error:")]
    for name, pattern in [("WordPress", r"\bwordpress\b"), ("jQuery", r"\bjquery\b"), ("PHP", r"\bphp\b")]:
        matches = [t for t in tech if re.search(pattern, t, re.IGNORECASE)]
        if matches:
            add("technology." + name.lower(), "info", name + " Detected",
                f"Page content or banners suggest {name}. No vulnerable version or exploit has been verified.",
                "Confirm the installed version with the system owner, check vendor support and applicable advisories, and update affected components when required.",
                {"matches": matches}, "No security impact is established by detection alone.",
                category="informational", confidence="low")
    return findings
