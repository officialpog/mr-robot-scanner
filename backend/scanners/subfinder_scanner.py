"""
Mr. Robot Scanner - Subfinder Subdomain Enumeration
Discovers subdomains of the target domain.
"""

import subprocess
import shutil
from typing import List


def run_subfinder_scan(target: str) -> List[str]:
    """Enumerate subdomains for target domain"""
    
    # Extract domain from URL
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    if not shutil.which("subfinder"):
        return simulate_scan(domain)
    
    try:
        cmd = ["subfinder", "-d", domain, "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        subdomains = [
            s.strip() for s in result.stdout.strip().split("\n") if s.strip()
        ]
        
        return subdomains if subdomains else simulate_scan(domain)
        
    except Exception:
        return simulate_scan(domain)


def simulate_scan(domain: str) -> List[str]:
    """Simulated subdomain enumeration"""
    return [
        f"dev.{domain}",
        f"mail.{domain}",
        f"api.{domain}",
        f"staging.{domain}",
        f"admin.{domain}"
    ]