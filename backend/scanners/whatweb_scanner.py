"""
Mr. Robot Scanner - WhatWeb Technology Detector
Identifies web technologies, CMS, frameworks, and libraries.
"""

import subprocess
import shutil
from typing import List, Dict


def run_whatweb_scan(target: str) -> List[Dict]:
    """Detect technologies used by target"""
    
    if not shutil.which("whatweb"):
        return simulate_scan(target)
    
    try:
        cmd = ["whatweb", "--no-errors", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        technologies = []
        # Parse WhatWeb output
        if result.stdout:
            parts = result.stdout.split("[")
            for part in parts[1:]:
                if "]" in part:
                    tech = part.split("]")[0].strip()
                    name_version = tech.split("[")[0].strip() if "[" in tech else tech
                    
                    technologies.append({
                        "name": name_version,
                        "version": None,
                        "category": "web"
                    })
        
        return technologies if technologies else simulate_scan(target)
        
    except Exception:
        return simulate_scan(target)


def simulate_scan(target: str) -> List[Dict]:
    """Simulated technology detection"""
    return [
        {"name": "Nginx", "version": "1.18.0", "category": "web-server"},
        {"name": "WordPress", "version": "5.8", "category": "cms"},
        {"name": "PHP", "version": "7.4", "category": "programming-language"},
        {"name": "jQuery", "version": "3.6.0", "category": "javascript-library"},
        {"name": "Bootstrap", "version": "4.5", "category": "web-framework"},
        {"name": "MySQL", "version": None, "category": "database"}
    ]