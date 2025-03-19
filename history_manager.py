import json
import os
from datetime import datetime
import threading

class HistoryManager:
    def __init__(self, history_file='url_history.json'):
        self.history_file = history_file
        self.lock = threading.Lock()
        self._ensure_history_file()
    
    def _ensure_history_file(self):
        """Create the history file if it doesn't exist"""
        if not os.path.exists(self.history_file):
            with open(self.history_file, 'w') as f:
                json.dump([], f)
    
    def add_url(self, url, is_phishing, probability, features_dict):
        """Add a URL to the history"""
        with self.lock:
            try:
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                history = []
            
            # Add the new entry
            entry = {
                'url': url,
                'is_phishing': is_phishing,
                'probability': probability,
                'features': features_dict,
                'timestamp': datetime.now().isoformat()
            }
            
            # Add to the beginning of the list
            history.insert(0, entry)
            
            # Keep only the last 100 entries
            history = history[:100]
            
            # Save the updated history
            with open(self.history_file, 'w') as f:
                json.dump(history, f)
    
    def get_history(self, limit=50):
        """Get the URL history"""
        with self.lock:
            try:
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
                return history[:limit]
            except (json.JSONDecodeError, FileNotFoundError):
                return []
    
    def clear_history(self):
        """Clear the URL history"""
        with self.lock:
            with open(self.history_file, 'w') as f:
                json.dump([], f)