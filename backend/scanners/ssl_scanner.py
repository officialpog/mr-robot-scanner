import ssl
import socket
import certifi
import time
import math

def run_ssl_scan(hostname: str, port: int = 443):
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse dates
                not_after = cert.get("notAfter")
                not_before = cert.get("notBefore")

                expiry_date = None
                days_until_expiry = None
                if not_after:
                    expiry_date = ssl.cert_time_to_seconds(not_after)
                    days_until_expiry = (expiry_date - time.time()) / 86400

                # Check weak ciphers
                weak_ciphers = version in ["TLSv1", "TLSv1.1"] or "NULL" in str(cipher) or "EXPORT" in str(cipher)

                # Check HSTS
                # We can't easily check HSTS here without HTTP, so we'll do it in headers scanner

                return {
                    "valid": True,
                    "hostname": hostname,
                    "port": port,
                    "issuer": ", ".join(f"{key}={value}" for rdn in cert.get("issuer", ()) for key, value in rdn) or None,
                    "subject": ", ".join(f"{key}={value}" for rdn in cert.get("subject", ()) for key, value in rdn) or None,
                    "not_before": not_before,
                    "not_after": not_after,
                    "expiry_days": math.floor(days_until_expiry) if days_until_expiry is not None else None,
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else None,
                    "weak_ciphers": weak_ciphers,
                    "san": cert.get("subjectAltName", []),
                }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "certificate_error": True, "error": str(e)}
    except ssl.SSLError as e:
        return {"valid": False, "error": f"SSL Error: {str(e)}"}
    except socket.timeout:
        return {"valid": False, "error": "Connection timeout"}
    except Exception as e:
        return {"valid": False, "error": str(e)}
