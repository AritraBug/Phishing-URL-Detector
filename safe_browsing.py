import requests
import os
from dotenv import load_dotenv

load_dotenv()

SAFE_BROWSING_API_KEY = os.getenv('SAFE_BROWSING_API_KEY', '')
SAFE_BROWSING_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

def check_url_safety(url):
    """
    Check if a URL is safe using Google Safe Browsing API
    Returns a dict with 'is_safe' and 'threats' keys
    """
    if not SAFE_BROWSING_API_KEY:
        print("Warning: No Safe Browsing API key provided. Skipping check.")
        return {'is_safe': True, 'threats': []}
    
    payload = {
        'client': {
            'clientId': 'phishing-url-detector',
            'clientVersion': '1.0.0'
        },
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    
    params = {'key': SAFE_BROWSING_API_KEY}
    
    try:
        response = requests.post(SAFE_BROWSING_URL, params=params, json=payload)
        if response.status_code == 200:
            data = response.json()
            is_safe = 'matches' not in data
            threats = []
            
            if not is_safe and 'matches' in data:
                for match in data['matches']:
                    threats.append({
                        'threat_type': match.get('threatType', 'Unknown'),
                        'platform_type': match.get('platformType', 'Unknown'),
                        'threat_entry_type': match.get('threatEntryType', 'Unknown')
                    })
            
            return {
                'is_safe': is_safe,
                'threats': threats
            }
        else:
            print(f"Safe Browsing API error: {response.status_code}")
            return {'is_safe': True, 'threats': []}
    except Exception as e:
        print(f"Error checking URL safety: {e}")
        return {'is_safe': True, 'threats': []}