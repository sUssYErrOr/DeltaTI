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
data_dir = project_root / 'collectors' / 'data' / 'feeds'
normalized_dir = Path(__file__).parent / 'normalized_data'
normalized_dir.mkdir(parents=True, exist_ok=True)

# Regular expression patterns for IOCs
IOC_PATTERNS = {
    'ipv4-addr': re.compile(r"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"),
    'url': re.compile(r"\\bhttps?://[^\\s,'\"]+\\b"),
    'file-sha256': re.compile(r"\\b[A-Fa-f0-9]{64}\\b"),
    'file-sha1': re.compile(r"\\b[A-Fa-f0-9]{40}\\b"),
    'file-md5': re.compile(r"\\b[A-Fa-f0-9]{32}\\b")
}

# Helper functions
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_csv(path: Path) -> List[Dict]:
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def load_json(path: Path) -> Optional[object]:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON in {path.name}")
        return None

# Normalization helpers
def build_record(indicator: str, ioc_type: str, source: str, raw: Optional[Dict] = None) -> Dict:
    return {
        'indicator': indicator,
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
    return [build_record(r['url'], 'url', 'urlhaus', r)
            for r in rows if r.get('url')]

def normalize_threatfox(path: Path) -> List[Dict]:
    records: List[Dict] = []
    rows = parse_csv(path)
    for r in rows:
        val = r.get('ioc') or r.get('ioc_value') or r.get('ioc_string')
        if not val:
            continue
        ioc_type = r.get('ioc_type') or 'unknown'
        records.append(build_record(val, ioc_type, 'threatfox', r))
    return records

def normalize_txt_list(path: Path, source: str, ioc_type: str = 'ipv4-addr') -> List[Dict]:
    lines = [l.strip() for l in path.read_text(encoding='utf-8').splitlines()
             if l.strip() and not l.startswith('#')]
    return [build_record(l, ioc_type, source) for l in lines]

def normalize_json_list(path: Path, source: str, key: str, ioc_type: str) -> List[Dict]:
    data = load_json(path)
    if not isinstance(data, list):
        return []
    return [build_record(e[key], ioc_type, source, e)
            for e in data if e.get(key)]

def normalize_generic(path: Path) -> List[Dict]:
    text = path.read_text(errors='ignore')
    seen = set()
    records: List[Dict] = []
    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in pattern.findall(text):
            if match not in seen:
                seen.add(match)
                records.append(build_record(match, ioc_type, path.stem))
    return records

def normalize_phishstats(path: Path) -> List[Dict]:
    return normalize_json_list(path, 'phishstats', key='url', ioc_type='url')

def normalize_otx(path: Path) -> List[Dict]:
    data = load_json(path)
    if not isinstance(data, dict):
        return []
    records: List[Dict] = []
    for ind in data.get('indicators', []):
        value = ind.get('indicator') or ind.get('id')
        if not value:
            continue
        ioc_type = ind.get('type') or 'unknown'
        records.append(build_record(value, ioc_type, 'otx', ind))
    return records

def normalize_abuseipdb(path: Path) -> List[Dict]:
    return normalize_json_list(path, 'abuseipdb', key='ipAddress', ioc_type='ipv4-addr')

def normalize_ciarmy(path: Path) -> List[Dict]:
    return normalize_txt_list(path, 'ciarmy')

def normalize_emerging_threats(path: Path) -> List[Dict]:
    return normalize_txt_list(path, 'emerging_threats')

# Map prefixes to parsing functions
PARSER_REGISTRY = {
    'urlhaus': normalize_urlhaus,
    'threatfox': normalize_threatfox,
    'feodo': lambda p: normalize_txt_list(p, 'feodo'),
    'spamhaus': lambda p: normalize_txt_list(p, 'spamhaus'),
    'ciarmy': normalize_ciarmy,
    'emerging': normalize_emerging_threats,
    'phishtank': lambda p: normalize_txt_list(p, 'phishtank', 'url'),
    'phishstats': normalize_phishstats,
    'otx': normalize_otx,
    # 'abuseipdb': normalize_abuseipdb
}

def normalize_all():
    """Iterate over raw feeds and produce normalized JSON outputs without duplicates."""
    summary = {'total': 0, 'by_source': {}}
    seen_indicators = set()

    for path in data_dir.iterdir():
        if not path.is_file():
            continue

        prefix = path.stem.split('_')[0]
        parser = PARSER_REGISTRY.get(prefix, normalize_generic)
        logger.info(f"Normalizing {path.name} (source: {prefix})")

        try:
            records = parser(path)
            unique_records = []

            for record in records:
                key = (record['indicator'], record['type'])
                if key not in seen_indicators:
                    seen_indicators.add(key)
                    unique_records.append(record)

            if unique_records:
                out_path = normalized_dir / f"normalized_{path.stem}.json"
                out_path.write_text(json.dumps(unique_records, ensure_ascii=False, indent=2))

                count = len(unique_records)
                summary['total'] += count
                summary['by_source'][prefix] = summary['by_source'].get(prefix, 0) + count
                logger.info(f"Wrote {count} unique indicators to {out_path.name}")
            else:
                logger.info(f"No new indicators found in {path.name}")

        except Exception:
            logger.exception(f"Failed to normalize {path.name}")

    logger.info(f"Normalization complete: {summary['total']} indicators across {len(summary['by_source'])} sources")

if __name__ == '__main__':
    normalize_all()