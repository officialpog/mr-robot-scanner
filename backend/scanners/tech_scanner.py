import httpx
import re

def run_tech_scan(url: str):
    if not url.startswith(("https://", "http://")):
        url = f"https://[{url}]" if ":" in url else f"https://{url}"

    technologies = []

    try:
        response = httpx.get(url, timeout=15, follow_redirects=True, headers={
            "User-Agent": "ReconScope/2.0"
        })

        text = response.text
        headers = dict(response.headers)

        # Server header
        server = headers.get("Server", headers.get("server", ""))
        if server:
            technologies.append(f"Server: {server}")

        # X-Powered-By
        powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if powered:
            technologies.append(f"Powered-By: {powered}")

        # CMS detection
        cms_patterns = {
            "WordPress": [r'wp-content', r'wp-includes', r'<meta name="generator" content="WordPress'],
            "Drupal": [r'Drupal', r'sites/default'],
            "Joomla": [r'Joomla', r'/media/jui/'],
            "Magento": [r'Magento', r'skin/frontend'],
            "Shopify": [r'Shopify', r'cdn.shopify.com'],
            "Ghost": [r'ghost.io', r'ghost/'],
            "Wix": [r'wix.com', r'wix-image'],
        }

        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    technologies.append(cms)
                    break

        # Framework detection
        fw_patterns = {
            "React": [r'reactroot', r'__REACT__', r'data-reactroot'],
            "Vue.js": [r'vue.js', r'__VUE__', r'data-v-'],
            "Angular": [r'ng-app', r'angular.js', r'@angular'],
            "Next.js": [r'__NEXT_DATA__'],
            "Nuxt.js": [r'__NUXT__'],
            "Django": [r'csrftoken', r'django'],
            "Flask": [r'flask'],
            "Laravel": [r'laravel_session'],
            "Ruby on Rails": [r'rails', r'csrf-param'],
        }

        for fw, patterns in fw_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    technologies.append(fw)
                    break

        # JS libraries
        js_patterns = {
            "jQuery": r'jquery[.-]?([0-9.]+)',
            "Bootstrap": r'bootstrap[/-]?([0-9.]+)',
            "Font Awesome": r'font[- ]?awesome',
            "Google Analytics": r'google-analytics|gtag|ga\(',
            "Google Tag Manager": r'googletagmanager',
        }

        for lib, pattern in js_patterns.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                version = match.group(1) if match and match.groups() else ""
                technologies.append(f"{lib} {version}".strip())

        # Programming language hints
        lang_patterns = {
            "PHP": [r'\.php', r'<\?php'],
            "ASP.NET": [r'\.aspx', r'__VIEWSTATE'],
            "Python": [r'python', r'wsgi'],
            "Node.js": [r'node.js', r'express'],
        }

        for lang, patterns in lang_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    technologies.append(lang)
                    break

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for t in technologies:
            key = t.lower()
            if key not in seen:
                seen.add(key)
                unique.append(t)

        return unique
    except Exception as e:
        return [f"Error: {str(e)}"]
