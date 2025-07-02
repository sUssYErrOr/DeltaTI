import os
import json
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), 'data', 'feeds')

def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

def timestamped_filename(prefix: str, ext: str = "json") -> str:
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    return f"{prefix}_{ts}.{ext}"

def save_to_file(name: str, content, ext: str = "json"):
    
    path = os.path.join(DATA_DIR, timestamped_filename(name, ext))
    with open(path, 'w', encoding='utf-8') as f:
        if ext == "json":
            json.dump(content, f, ensure_ascii=False, indent=2)
        else:
            f.write(content)