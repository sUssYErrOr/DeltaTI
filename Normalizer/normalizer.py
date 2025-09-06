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

def normalize_malshare_getlist(path: Path) -> List[Dict]:
    # Accept both JSON list and plain text
    records = []
    j = load_json(path)
    if isinstance(j, list):
        for item in j:
            # try typical fields
            sha256 = item.get("sha256") or item.get("sha256_hash")
            md5 = item.get("md5")
            if sha256:
                records.append(build_record(sha256, "file-sha256", "malshare", item))
            elif md5:
                records.append(build_record(md5, "file-md5", "malshare", item))
            else:
                # scan entire item
                for v in item.values():
                    if isinstance(v, str):
                        for t, pat in IOC_PATTERNS.items():
                            m = pat.search(v)
                            if m:
                                records.append(build_record(m.group(), t, "malshare", item))
                                break
    else:
        # text fallback: search with regex
        txt = path.read_text(encoding='utf-8')
        for t, pat in IOC_PATTERNS.items():
            for m in pat.findall(txt):
                records.append(build_record(m, t, "malshare", {"src": "text"}))
    return records


def normalize_dshield_openioc(path: Path) -> List[Dict]:
    """
    Normalize DShield OpenIOC-like files. Handles:
      - JSON arrays/objects (tries common keys first then falls back to scanning the whole item)
      - XML documents (parses element text + attributes)
      - Plain text (line-based extraction)

    Returns a list of indicator records using build_record().
    """
    records: List[Dict] = []
    seen = set()  # dedupe per-file by (value, type)

    # Helper to clean extracted token
    def clean_val(v: str) -> str:
        return v.strip().strip('"\'`<>[](),;.')

    # Prefer URL matching first to avoid extracting IPs from inside URLs
    ordered_types = ['url', 'ipv4-addr', 'file-sha256', 'file-sha1', 'file-md5']

    def extract_from_text_blob(text: str, raw_obj=None):
        # scan using ordered_types to avoid false positives
        for t in ordered_types:
            pat = IOC_PATTERNS.get(t)
            if not pat:
                continue
            for m in pat.findall(text):
                val = clean_val(m)
                key = (val, t)
                if val and key not in seen:
                    seen.add(key)
                    records.append(build_record(val, t, "dshield", raw_obj or {}))

    # Try to parse JSON first (if file appears to be JSON)
    try:
        data = load_json(path)
    except Exception:
        data = None

    if data is not None:
        # JSON successfully loaded
        if isinstance(data, list):
            for item in data:
                # Collect candidate strings from likely keys
                candidates = []
                if isinstance(item, dict):
                    for k in ("ioc", "indicator", "ip", "domain", "value", "description", "data"):
                        v = item.get(k)
                        if isinstance(v, str) and v.strip():
                            candidates.append(v)
                    # also scan all string values in the dict
                    for v in item.values():
                        if isinstance(v, str):
                            candidates.append(v)
                elif isinstance(item, str):
                    candidates.append(item)

                # Try candidates first
                for cand in candidates:
                    extract_from_text_blob(cand, raw_obj=item)

                # If nothing found for this item, fallback to scanning the whole item JSON text
                if not any((rec for rec in records if rec['raw'] is item)):
                    try:
                        txt = json.dumps(item)
                    except Exception:
                        txt = str(item)
                    extract_from_text_blob(txt, raw_obj=item)

        elif isinstance(data, dict):
            # Single JSON object: scan its values and full dump
            candidates = []
            for v in data.values():
                if isinstance(v, str):
                    candidates.append(v)
            for cand in candidates:
                extract_from_text_blob(cand, raw_obj=data)

            # fallback scan whole doc
            try:
                txt = json.dumps(data)
            except Exception:
                txt = str(data)
            extract_from_text_blob(txt, raw_obj=data)

        else:
            # JSON of unexpected type: convert to string and scan
            extract_from_text_blob(str(data), raw_obj=data)

        return records

    # Not JSON — read raw text
    text = path.read_text(encoding='utf-8', errors='ignore').strip()
    if not text:
        return records

    # Quick detection for XML content
    if text.lstrip().startswith("<?xml") or ("<ioc" in text.lower() or "<openioc" in text.lower()):
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
            parts = []
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    parts.append(elem.text.strip())
                for v in elem.attrib.values():
                    if isinstance(v, str) and v.strip():
                        parts.append(v.strip())
            blob = "\n".join(parts)
            extract_from_text_blob(blob, raw_obj={})
            return records
        except Exception:
            # fall back to plain-text scanning below
            pass

    # Plain text: try line-by-line and whole-text scan
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for line in lines:
        extract_from_text_blob(line, raw_obj={})

    # final whole-text scan (catches multi-line IOCs)
    extract_from_text_blob(text, raw_obj={})

    return records

    """
    Normalize DShield Threatfeeds files. Handles:
      - JSON arrays/objects (tries common keys first then falls back to scanning the whole item)
      - XML documents (parses element text + attributes)
      - Plain text (line-based extraction)

    Returns a list of indicator records using build_record().
    """
    records: List[Dict] = []
    seen = set()  # dedupe per-file by (value, type)

    def clean_val(v: str) -> str:
        return v.strip().strip('"\'`<>[](),;.')

    ordered_types = ['url', 'ipv4-addr', 'file-sha256', 'file-sha1', 'file-md5']

    def extract_from_text_blob(text: str, raw_obj=None):
        for t in ordered_types:
            pat = IOC_PATTERNS.get(t)
            if not pat:
                continue
            for m in pat.findall(text):
                val = clean_val(m)
                key = (val, t)
                if val and key not in seen:
                    seen.add(key)
                    records.append(build_record(val, t, "dshield_threatfeeds", raw_obj or {}))

    # --- Try JSON first ---
    try:
        data = load_json(path)
    except Exception:
        data = None

    if data is not None:
        if isinstance(data, list):
            for item in data:
                candidates = []
                if isinstance(item, dict):
                    for k in ("ioc", "indicator", "ip", "domain", "value", "description", "data"):
                        v = item.get(k)
                        if isinstance(v, str) and v.strip():
                            candidates.append(v)
                    for v in item.values():
                        if isinstance(v, str):
                            candidates.append(v)
                elif isinstance(item, str):
                    candidates.append(item)

                for cand in candidates:
                    extract_from_text_blob(cand, raw_obj=item)

                if not any((rec for rec in records if rec.get('raw') is item)):
                    try:
                        txt = json.dumps(item)
                    except Exception:
                        txt = str(item)
                    extract_from_text_blob(txt, raw_obj=item)

        elif isinstance(data, dict):
            candidates = []
            for v in data.values():
                if isinstance(v, str):
                    candidates.append(v)
            for cand in candidates:
                extract_from_text_blob(cand, raw_obj=data)

            try:
                txt = json.dumps(data)
            except Exception:
                txt = str(data)
            extract_from_text_blob(txt, raw_obj=data)

        else:
            extract_from_text_blob(str(data), raw_obj=data)

        return records

    # --- Not JSON → try text ---
    text = path.read_text(encoding='utf-8', errors='ignore').strip()
    if not text:
        return records

    # --- Detect XML ---
    if text.lstrip().startswith("<?xml") or ("<feed" in text.lower() or "<entry" in text.lower()):
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
            parts = []
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    parts.append(elem.text.strip())
                for v in elem.attrib.values():
                    if isinstance(v, str) and v.strip():
                        parts.append(v.strip())
            blob = "\n".join(parts)
            extract_from_text_blob(blob, raw_obj={})
            return records
        except Exception:
            pass

    # --- Fallback: plain-text line-by-line ---
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for line in lines:
        extract_from_text_blob(line, raw_obj={})

    extract_from_text_blob(text, raw_obj={})

    return records

def normalize_bazaar_recent(path: Path) -> List[Dict]:
    # CSV may include columns like sha256, url, filename, etc.
    rows = parse_csv(path)
    records = []
    for r in rows:
        # common fields
        sha256 = r.get("sha256") or r.get("sha256_hash")
        md5 = r.get("md5")
        url = r.get("url")
        fname = r.get("file_name") or r.get("filename")

        if sha256:
            records.append(build_record(sha256, "file-sha256", "bazaar_recent", r))
        if md5:
            records.append(build_record(md5, "file-md5", "bazaar_recent", r))
        if url:
            records.append(build_record(url, "url", "bazaar_recent", r))
        # fallback: scan all values with regex
        if not (sha256 or md5 or url):
            for v in r.values():
                if isinstance(v, str):
                    for t, pat in IOC_PATTERNS.items():
                        m = pat.search(v)
                        if m:
                            records.append(build_record(m.group(), t, "bazaar_recent", r))
                            break
    return records


def normalize_bazaar_yara_stats(path: Path) -> List[Dict]:
    data = load_json(path)
    if not data:
        return []
    records = []
    # Try to find obvious fields
    # e.g. entries might contain 'sample_hash', 'filename', 'url' etc.
    if isinstance(data, dict):
        # iterate through values looking for dicts/lists containing IOCs
        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        yield from walk(v)
                    else:
                        yield (k, v)
            elif isinstance(obj, list):
                for item in obj:
                    yield from walk(item)
        for k, v in walk(data):
            if isinstance(v, str):
                # cheap heuristic: hash lengths or url pattern
                if re.fullmatch(r"[A-Fa-f0-9]{64}", v):
                    records.append(build_record(v, "file-sha256", "bazaar_yara", data))
                elif v.startswith("http://") or v.startswith("https://"):
                    records.append(build_record(v, "url", "bazaar_yara", data))
    # fallback: search raw text
    if not records:
        txt = json.dumps(data)
        for t, pat in IOC_PATTERNS.items():
            for m in pat.findall(txt):
                records.append(build_record(m, t, "bazaar_yara", data))
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
    'otx': normalize_otx,
    'bazaar_yara_stats': normalize_bazaar_yara_stats,
    'bazaar_recent': normalize_bazaar_recent,
    'dshield_openioc': normalize_dshield_openioc,
    'malshare_getlist': normalize_malshare_getlist,
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