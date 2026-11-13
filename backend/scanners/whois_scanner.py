import whois
import httpx
import ipaddress
from urllib.parse import quote


def run_rdap_scan(domain):
    """Use HTTPS when a registry's legacy WHOIS service is unavailable."""
    response = httpx.get(
        'https://rdap.org/domain/' + quote(domain, safe=''),
        headers={'Accept': 'application/rdap+json'},
        timeout=10, follow_redirects=True,
    )
    response.raise_for_status()
    data = response.json()
    if data.get('objectClassName') != 'domain' or not data.get('ldhName'):
        raise ValueError('RDAP did not return a domain registration record')
    events = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
    registrar = None
    for entity in data.get('entities', []):
        if 'registrar' in entity.get('roles', []):
            card = entity.get('vcardArray') or ['vcard', []]
            registrar = next((p[3] for p in card[1] if len(p) > 3 and p[0] == 'fn'), None)
            registrar = registrar or entity.get('handle')
            break
    return {
        'domain_name': data['ldhName'], 'registrar': registrar,
        'creation_date': events.get('registration'),
        'expiration_date': events.get('expiration'),
        'updated_date': events.get('last changed'),
        'name_servers': [n['ldhName'] for n in data.get('nameservers', []) if n.get('ldhName')],
        'status': ', '.join(data.get('status', [])) or None,
        'source': 'RDAP',
    }

def run_whois_scan(domain: str):
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        return {'error': 'Domain registration lookup is not applicable to an IP address.', 'domain_name': domain}
    try:
        w = whois.whois(domain, quiet=True)

        def safe_get(attr):
            val = getattr(w, attr, None)
            if isinstance(val, list):
                return val[0] if val else None
            return val

        result = {
            "domain_name": safe_get("domain_name"),
            "registrar": safe_get("registrar"),
            "creation_date": str(safe_get("creation_date")) if safe_get("creation_date") is not None else None,
            "expiration_date": str(safe_get("expiration_date")) if safe_get("expiration_date") is not None else None,
            "updated_date": str(safe_get("updated_date")) if safe_get("updated_date") is not None else None,
            "name_servers": ([getattr(w, "name_servers")] if isinstance(getattr(w, "name_servers", None), str) else (getattr(w, "name_servers", None) or [])),
            "status": safe_get("status"),
            "emails": safe_get("emails"),
            "dnssec": safe_get("dnssec"),
            "org": safe_get("org"),
            "country": safe_get("country"),
        }
        if any(v for k, v in result.items() if k != 'domain_name'):
            result['source'] = 'WHOIS'
            return result
    except Exception:
        pass
    try:
        return run_rdap_scan(whois.extract_domain(domain))
    except Exception:
        return {
            'error': 'Registration data unavailable: WHOIS returned no usable data and the HTTPS RDAP fallback failed. The registry may be unreachable, rate limiting requests, or have no public record. Try again later.',
            'domain_name': domain,
        }
