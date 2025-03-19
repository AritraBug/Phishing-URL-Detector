import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
import tld
from datetime import datetime
import socket
import ssl
import numpy as np

def extract_features(url):
    """
    Extract features from a URL for phishing detection
    Returns a list of 30 features
    """
    features = []
    
    # Preprocess the URL
    url = url.lower()
    if not url.startswith('http'):
        url = 'http://' + url
    
    # Parse the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Basic Features
    features.append(len(url))  # 1. URL Length
    features.append(len(domain))  # 2. Domain Length
    features.append(url.count('.'))  # 3. Dot Count
    features.append(len(domain.split('.')) - 1)  # 4. Subdomain Count
    features.append(1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0)  # 5. Has IP Address
    features.append(1 if '@' in url else 0)  # 6. Contains @ Symbol
    features.append(1 if '//' in parsed_url.path else 0)  # 7. Contains // in Path
    features.append(1 if '-' in domain else 0)  # 8. Contains - in Domain
    
    # Suspicious Words
    suspicious_words = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
    features.append(1 if any(word in url for word in suspicious_words) else 0)  # 9. Contains Suspicious Words
    
    # URL Shorteners
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'youtu.be']
    features.append(1 if any(service in domain for service in shortening_services) else 0)  # 10. Is URL Shortened

    # Domain Age
    domain_age = 0
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            domain_age = (datetime.now() - creation_date).days
    except:
        pass
    features.append(min(domain_age, 1000))  # 11. Domain Age (capped at 1000)

    # SSL Certificate
    features.append(1 if parsed_url.scheme == 'https' else 0)  # 12. Has HTTPS
    has_valid_ssl = 0
    if parsed_url.scheme == 'https':
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    has_valid_ssl = 1
        except:
            pass
    features.append(has_valid_ssl)  # 13. Valid SSL Certificate

    # URL Structure
    features.append(len(parsed_url.path))  # 14. Path Length
    features.append(len(parsed_url.query.split('&')) if parsed_url.query else 0)  # 15. Query Parameter Count

    # Additional Suspicious Features
    features.append(url.count('?'))  # 16. Number of '?'
    features.append(url.count('='))  # 17. Number of '='
    features.append(url.count('%'))  # 18. Number of '%'
    features.append(url.count('#'))  # 19. Number of '#'

    # Google Safe Browsing API Check (Placeholder)
    features.append(0)  # 20. Safe Browsing Flag (requires API check)

    # Fetch Page Content
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        # HTML-based Features
        features.append(len(soup.find_all('a', href=True)))  # 21. Number of links
        features.append(len([1 for link in soup.find_all('a', href=True) if link['href'].startswith('http') and domain not in link['href']]))  # 22. External Links
        features.append(len(soup.find_all('form')))  # 23. Form Count
        features.append(1 if any(form.find('input', {'type': 'password'}) for form in soup.find_all('form')) else 0)  # 24. Has Login Form
    except:
        features.extend([0, 0, 0, 0])  # If request fails, default values

    # More Features
    features.append(1 if re.search(r"(?:https?:\/\/)?(?:www\.)?[^.]+\.(?:com|net|org|gov|edu|mil|int|info|biz|co|tv|me|io|xyz)", url) else 0)  # 25. Common TLD
    features.append(len(re.findall(r'[0-9]', url)))  # 26. Number of digits in URL
    features.append(1 if 'https' in domain else 0)  # 27. Contains 'https' in domain
    features.append(1 if len(domain) > 20 else 0)  # 28. Long domain name
    features.append(1 if re.search(r"free|offer|click|win|bargain|deal", url) else 0)  # 29. Contains Marketing Words
    features.append(1 if parsed_url.netloc.count('.') >= 3 else 0)  # 30. Multiple Subdomains
    
    return features


def get_feature_names():
    """Return the names of all features in the same order as extract_features"""
    return [
        "URL Length",
        "Domain Length",
        "Dot Count",
        "Subdomain Count",
        "Has IP Address",
        "Contains @ Symbol",
        "Contains // in Path",
        "Contains - in Domain",
        "Contains Suspicious Words",
        "Is URL Shortened",
        "Domain Age (days)",
        "Has HTTPS",
        "Valid SSL Certificate",
        "Path Length",
        "Query Parameter Count",
        "External Link Count",
        "Form Count",
        "Has Login Form"
    ]