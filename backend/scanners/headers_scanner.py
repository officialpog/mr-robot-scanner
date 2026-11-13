import httpx

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

INFO_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
]

def run_headers_scan(url: str):
    if not url.startswith(("https://", "http://")):
        url = f"https://[{url}]" if ":" in url else f"https://{url}"

    try:
        response = httpx.get(url, timeout=15, follow_redirects=True, headers={
            "User-Agent": "ReconScope/2.0"
        })

        headers = dict(response.headers)
        header_keys = [k.lower() for k in headers.keys()]

        present = []
        missing = []
        info_leaks = []

        for h in SECURITY_HEADERS:
            if h.lower() in header_keys:
                present.append(h)
            else:
                missing.append(h)

        for h in INFO_HEADERS:
            if h.lower() in header_keys:
                info_leaks.append(f"{h}: {headers.get(h, headers.get(h.lower(), 'N/A'))}")

        # Check HSTS specifically
        hsts = headers.get("Strict-Transport-Security", headers.get("strict-transport-security", ""))
        hsts_issues = []
        if not hsts:
            hsts_issues.append("HSTS header missing")
        elif "max-age" not in hsts.lower():
            hsts_issues.append("HSTS missing max-age directive")
        elif "includesubdomains" not in hsts.lower():
            hsts_issues.append("HSTS missing includeSubDomains")

        return {
            "status_code": response.status_code,
            "present": present,
            "missing": missing,
            "info_leaks": info_leaks,
            "hsts_issues": hsts_issues,
            "raw": {k: v for k, v in headers.items() if k.lower() in [h.lower() for h in SECURITY_HEADERS + INFO_HEADERS]},
        }
    except httpx.TimeoutException:
        return {"error": "Request timeout", "present": [], "missing": [], "info_leaks": [], "hsts_issues": []}
    except Exception as e:
        return {"error": str(e), "present": [], "missing": [], "info_leaks": [], "hsts_issues": []}
