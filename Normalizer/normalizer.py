import json
import csv
import re
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Directories
project_root = Path(__file__).parent.parent
normalized_dir = Path(__file__).parent / 'normalized_data'
normalized_dir.mkdir(parents=True, exist_ok=True)

IOC_PATTERNS = {
    'ipv4-addr': re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    'url': re.compile(r"\bhttps?://[^\s,'\"]+\b"),
    'file-sha256': re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    'file-sha1': re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    'file-md5': re.compile(r"\b[A-Fa-f0-9]{32}\b")
}

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_csv(path: Path) -> List[Dict]:
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f, skipinitialspace=True))

def load_json(path: Path) -> Optional[object]:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON in {path.name}")
        return None

def build_record(indicator: str, ioc_type: str, source: str, raw: Optional[Dict] = None) -> Dict:
    return {
        'indicator': indicator.strip(),
        'type': ioc_type,
        'source': source,
        'confidence': 80,
        'first_seen': now_iso(),
        'last_seen': now_iso(),
        'tags': [],
        'raw': raw or {}
    }

def normalize_urlhaus(path: Path) -> List[Dict]:
    rows = parse_csv(path)
    records: List[Dict] = []
    for r in rows:
        url = r.get('url') or r.get('URL')
        if not url:
            continue
        status = r.get('url_status', '').lower()
        conf = 90 if status == 'online' else 60
        date = r.get('dateadded')
        rec = build_record(url, 'url', 'urlhaus', r)
        rec['confidence'] = conf
        rec['first_seen'] = date or rec['first_seen']
        rec['last_seen'] = date or rec['last_seen']
        threat = r.get('threat')
        if threat:
            rec['tags'] = [threat]
        records.append(rec)
    return records

def normalize_threatfox(path: Path) -> List[Dict]:
    rows = parse_csv(path)
    records: List[Dict] = []
    for r in rows:
        val = r.get('ioc_value') or r.get('ioc')
        if not val:
            continue
        ioc_type = r.get('ioc_type', 'unknown').lower()
        if ioc_type == 'ip:port':
            val = val.split(':')[0]
            ioc_type = 'ipv4-addr'
        rec = build_record(val, ioc_type, 'threatfox', r)
        try:
            rec['confidence'] = int(r.get('confidence_level', 50))
        except (ValueError, TypeError):
            rec['confidence'] = 50
        first = r.get('first_seen_utc') or r.get('first_seen')
        last = r.get('last_seen_utc') or r.get('last_seen')
        if first:
            rec['first_seen'] = first
        if last:
            rec['last_seen'] = last
        tags = r.get('tags')
        if tags:
            rec['tags'] = [t.strip() for t in tags.split(',') if t.strip()]
        records.append(rec)
    return records

def normalize_txt_list(path: Path, source: str, ioc_type: str = 'ipv4-addr') -> List[Dict]:
    lines = [l.strip() for l in path.read_text(encoding='utf-8').splitlines()
             if l.strip() and not l.startswith('#')]
    return [build_record(l, ioc_type, source) for l in lines]

def normalize_json_list(path: Path, source: str, key: str, ioc_type: str) -> List[Dict]:
    data = load_json(path)
    if not isinstance(data, list):
        return []
    return [build_record(e.get(key), ioc_type, source, e)
            for e in data if e.get(key)]

def normalize_generic(path: Path) -> List[Dict]:
    text = path.read_text(errors='ignore')
    seen = set()
    records: List[Dict] = []
    for t, pat in IOC_PATTERNS.items():
        for m in pat.findall(text):
            if m not in seen:
                seen.add(m)
                records.append(build_record(m, t, path.stem))
    return records

def normalize_phishstats(path: Path) -> List[Dict]:
    return normalize_json_list(path, 'phishstats', key='url', ioc_type='url')

def normalize_otx(path: Path) -> List[Dict]:
    data = load_json(path)
    if not isinstance(data, dict):
        return []
    records: List[Dict] = []
    for ind in data.get('indicators', []):
        val = ind.get('indicator') or ind.get('id')
        if not val:
            continue
        rec = build_record(val, ind.get('type','unknown'), 'otx', ind)
        records.append(rec)
    return records

PARSER_REGISTRY = {
    'urlhaus': lambda p: normalize_txt_list(p, 'urlhaus', 'url'),
    'threatfox': lambda p: normalize_txt_list(p, 'threatfox'),
    'feodo': lambda p: normalize_txt_list(p, 'feodo'),
    'spamhaus': lambda p: normalize_txt_list(p, 'spamhaus'),
    'ciarmy': lambda p: normalize_txt_list(p, 'ciarmy'),
    'emerging': lambda p: normalize_txt_list(p, 'emerging_threats'),
    'phishtank': lambda p: normalize_txt_list(p, 'phishtank', 'url'),
    'phishstats': normalize_phishstats,
    'otx': normalize_otx
}

def normalize_all(file_paths: List[Path] = None):
    """
    If file_paths is given, only normalize those files; otherwise normalize all raw feeds.
    Skip any file already normalized (filename starts with 'normalized_').
    """
    # Determine candidates
    if file_paths is None:
        candidates = [
            p for p in data_dir.iterdir()
            if p.is_file() and not p.name.startswith("normalized_")
        ]
    else:
        candidates = [
            p for p in file_paths
            if p.is_file() and not p.name.startswith("normalized_")
        ]

    summary = {'total': 0, 'by_source': {}}
    seen = set()

    for path in candidates:
        prefix = path.stem.split('_')[0]
        parser = PARSER_REGISTRY.get(prefix, normalize_generic)
        logger.info(f"Normalizing {path.name} (source: {prefix})")

        try:
            records = parser(path)
            unique = []
            for rec in records:
                key = (rec['indicator'], rec['type'])
                if key not in seen:
                    seen.add(key)
                    unique.append(rec)

            if unique:
                out = normalized_dir / f"normalized_{path.stem}.json"
                out.write_text(json.dumps(unique, ensure_ascii=False, indent=2))
                cnt = len(unique)
                summary['total'] += cnt
                summary['by_source'][prefix] = summary['by_source'].get(prefix, 0) + cnt
                logger.info(f"Wrote {cnt} indicators to {out.name}")
            else:
                logger.info(f"No new indicators in {path.name}")
        except Exception:
            logger.exception(f"Failed to normalize {path.name}")

    logger.info(
        f"Normalization complete: {summary['total']} indicators across {len(summary['by_source'])} sources"
    )

if __name__ == '__main__':
    data_dir = project_root / 'collectors' / 'data' / 'feeds'
    normalize_all(list(data_dir.glob("*")))