# normalizer.py
import json
import csv
import re
import logging
import uuid
import xml.etree.ElementTree as ET
from typing import List
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any

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

# Fallback regex patterns
IOC_PATTERNS = {
    'ipv4-addr': re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    'url': re.compile(r"\bhttps?://[^\s,'\"]+\b"),
    'file-sha256': re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    'file-sha1': re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    'file-md5': re.compile(r"\b[A-Fa-f0-9]{32}\b")
}

IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
URL_RE = re.compile(r"https?://[^\s'\",]+")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)

# Helpers
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_csv(path: Path) -> List[Dict[str, str]]:
    """Read CSV into list of dicts, trimming spaces after delimiters."""
    with path.open(newline='', encoding='utf-8', errors='ignore') as f:
        return list(csv.DictReader(f, skipinitialspace=True))

def load_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        logger.debug(f"Invalid JSON in {path.name}")
        return None
    except Exception as e:
        logger.debug(f"Error reading JSON {path.name}: {e}")
        return None

def gen_id(prefix: str, value: str) -> str:
    # stable UUID based on namespace+value
    return f"{prefix}--{uuid.uuid5(uuid.NAMESPACE_URL, value)}"

# Basic record builder (keeps backward compatibility)
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

# --------------------------
# Existing specific normalizers (keep behavior)
# --------------------------

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
        rec['last_seen'] = r.get('last_online') or rec['last_seen']
        tags = []
        if r.get('threat'):
            tags.append(r['threat'])
        if r.get('tags'):
            tags.extend([t.strip() for t in r['tags'].split(',') if t.strip()])
        rec['tags'] = tags
        records.append(rec)
    return records

def normalize_threatfox(path: Path) -> List[Dict]:
    rows = parse_csv(path)
    records: List[Dict] = []
    for r in rows:
        # threatfox CSV header: "first_seen_utc","ioc_id","ioc_value","ioc_type",...
        val = (r.get('ioc_value') or r.get('ioc') or r.get('ioc_value ' )).strip() if (r.get('ioc_value') or r.get('ioc')) else None
        if not val:
            # fallback: try generic regex extraction from raw line
            text = ",".join([v for v in r.values() if v])
            for t, regex in IOC_PATTERNS.items():
                m = regex.search(text)
                if m:
                    val = m.group()
                    ioc_t = t
                    break
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
        rec['first_seen'] = r.get('first_seen_utc') or r.get('first_seen') or rec['first_seen']
        rec['last_seen'] = r.get('last_seen_utc') or r.get('last_seen') or rec['last_seen']
        tags = []
        if r.get('threat_type'):
            tags.append(r['threat_type'])
        if r.get('malware_printable'):
            tags.append(r['malware_printable'])
        if r.get('tags'):
            tags.extend([t.strip() for t in r['tags'].split(',') if t.strip()])
        rec['tags'] = tags
        records.append(rec)
    return records

# --------------------------
# New parsers for extra sources
# --------------------------

def normalize_bazaar_yara_stats(path: Path) -> List[Dict]:
    """
    MalwareBazaar / abuse.ch yara-stats JSON -> produce records representing YARA rule names.
    This is not a typical IOC feed (it's YARA metadata), so use type 'yara-rule'.
    """
    records: List[Dict] = []
    data = load_json(path)
    if not data:
        logger.debug(f"[bazaar_yara_stats] No JSON data in {path.name}, falling back to generic parsing.")
        return normalize_generic(path)

    # Accept list or dict with items
    items = data if isinstance(data, list) else data.get('yara_stats') or data.get('results') or []
    if isinstance(items, dict):
        # single-object mapping, convert to list
        items = [items]

    for it in items:
        # look for likely fields: 'rule', 'yara_rule', 'name'
        name = None
        if isinstance(it, dict):
            name = it.get('rule') or it.get('yara_rule') or it.get('name')
        if not name:
            # try stringified item
            name = str(it)
        if not name:
            continue
        rec = build_record(name, 'yara-rule', 'bazaar_yara_stats', it if isinstance(it, dict) else {})
        records.append(rec)
    return records

def normalize_bazaar_recent(path: Path) -> List[Dict]:
    """
    bazaar recent CSV (or JSON) -> attempt to extract URLs, sample hashes, domains.
    """
    records: List[Dict] = []
    # try JSON first
    data = load_json(path)
    if data:
        # if JSON is list/dict of samples
        if isinstance(data, list):
            for entry in data:
                # likely keys: 'url', 'sha256', 'md5', 'domain'
                if isinstance(entry, dict):
                    for key in ('url', 'ioc', 'ioc_value', 'sha256', 'md5', 'domain', 'filename'):
                        if entry.get(key):
                            # pick appropriate type
                            if key in ('sha256',):
                                rec_type = 'file-sha256'
                            elif key in ('md5',):
                                rec_type = 'file-md5'
                            elif key == 'url' or key.startswith('http'):
                                rec_type = 'url'
                            else:
                                rec_type = 'unknown'
                            rec = build_record(str(entry.get(key)), rec_type, 'bazaar_recent', entry)
                            records.append(rec)
                            break
        else:
            # dict -> try keys
            for key in ('url','sha256','md5','domain'):
                if data.get(key):
                    rec_type = 'url' if key == 'url' else ('file-sha256' if key == 'sha256' else 'unknown')
                    records.append(build_record(str(data.get(key)), rec_type, 'bazaar_recent', data))
        if records:
            return records

    # fallback to CSV parsing
    try:
        rows = parse_csv(path)
        for r in rows:
            # try common columns
            for col in ('url','ioc_value','sha256','md5','domain','ioc'):
                if r.get(col):
                    if col == 'url':
                        t = 'url'
                    elif col == 'sha256':
                        t = 'file-sha256'
                    elif col == 'md5':
                        t = 'file-md5'
                    elif col == 'domain':
                        t = 'domain'
                    else:
                        # attempt to detect via regex
                        val = r.get(col)
                        t = detect_ioc_type(val)
                    records.append(build_record(r.get(col), t, 'bazaar_recent', r))
                    break
    except Exception:
        logger.debug(f"[bazaar_recent] CSV parse failed for {path.name}, falling back to generic extraction.")
        return normalize_generic(path)

    return records

def extract_iocs_from_text_blob(text: str) -> List[str]:
    """Find likely IOCs in a text blob (IPs, URLs, domains)."""
    found = set()
    for regex in (URL_RE, IP_RE, DOMAIN_RE):
        for m in regex.findall(text):
            found.add(m.strip())
    return sorted(found)


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


def normalize_malshare_getlist(path: Path) -> List[Dict]:
    """
    MalShare getlist might return plain text (one sample per line) or JSON.
    We'll accept both and try to infer type (sha256, filename, url).
    """
    records: List[Dict] = []
    data = load_json(path)
    if data:
        # if a JSON list of strings or objects
        if isinstance(data, list):
            for it in data:
                if isinstance(it, str):
                    t = detect_ioc_type(it)
                    records.append(build_record(it, t, 'malshare_getlist', {}))
                elif isinstance(it, dict):
                    # find likely fields
                    val = it.get('sha256') or it.get('sha1') or it.get('filename') or it.get('url')
                    if val:
                        rec_type = 'file-sha256' if it.get('sha256') else 'file-sha1' if it.get('sha1') else 'url'
                        records.append(build_record(val, rec_type, 'malshare_getlist', it))
        else:
            # non-list JSON
            text = json.dumps(data)
            return normalize_generic(path)
    else:
        # try plain text: one entry per line
        text = path.read_text(encoding='utf-8', errors='ignore')
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            t = detect_ioc_type(line)
            records.append(build_record(line, t, 'malshare_getlist', {}))

    return records

# --------------------------
# Generic helpers
# --------------------------

def detect_ioc_type(value: str) -> str:
    """
    Try to detect IOC type using patterns, otherwise return 'unknown'
    """
    if not value or not isinstance(value, str):
        return 'unknown'
    value = value.strip()
    for t, regex in IOC_PATTERNS.items():
        if regex.fullmatch(value) or regex.search(value):
            return t
    # quick heuristics
    if value.startswith('http://') or value.startswith('https://'):
        return 'url'
    if ':' in value and re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", value):
        return 'ipv4-addr'
    return 'unknown'

# --------------------------
# Other existing parsers
# --------------------------

def normalize_txt_list(path: Path, source: str, ioc_type: str = 'ipv4-addr') -> List[Dict]:
    lines = [l.strip() for l in path.read_text(encoding='utf-8').splitlines()
             if l.strip() and not l.startswith('#')]
    records: List[Dict] = []
    for line in lines:
        matched = False
        for t, regex in IOC_PATTERNS.items():
            match = regex.search(line)
            if match:
                records.append(build_record(match.group(), t, source))
                matched = True
                break
        if not matched:
            records.append(build_record(line, ioc_type, source))
    return records

def normalize_json_list(path: Path, source: str, key: str, ioc_type: str) -> List[Dict]:
    data = load_json(path)
    if not isinstance(data, list):
        return []
    return [build_record(str(e.get(key)), ioc_type, source, e)
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

# --------------------------
# PARSER_REGISTRY (updated)
# --------------------------
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
    # newly added sources
    'bazaar_yara_stats': normalize_bazaar_yara_stats,
    'bazaar_recent': normalize_bazaar_recent,
    'dshield_openioc': normalize_dshield_openioc,
    'malshare_getlist': normalize_malshare_getlist,
}

# --------------------------
# normalize_all — accept optional list of Paths (backwards compatible)
# --------------------------
def normalize_all(paths: Optional[List[Path]] = None) -> None:
    """
    Normalize either:
      - only the provided list of Path objects (new files),
      - or (if paths is None) scan data_dir and normalize recent files.

    Produces normalized_{original_stem}.json files in normalized_dir.
    Skips existing normalized_* files (doesn't overwrite).
    """
    summary = {'total': 0, 'by_source': {}}
    seen = set()

    files_to_process: List[Path] = []
    if paths:
        files_to_process = [p for p in paths if p.is_file()]
    else:
        # default behavior: process everything in data_dir (but skip already normalized)
        for p in sorted(data_dir.iterdir()):
            if not p.is_file():
                continue
            files_to_process.append(p)

    for path in files_to_process:
        prefix = path.stem.split('_')[0]
        out_path = normalized_dir / f"normalized_{path.stem}.json"
        if out_path.exists():
            logger.info(f"[Skip] Normalized file already exists for {path.name} -> {out_path.name}")
            continue

        parser = PARSER_REGISTRY.get(prefix, normalize_generic)
        logger.info(f"Normalizing {path.name} (source: {prefix})")
        try:
            records = parser(path)
            unique = []
            for rec in records:
                key = (rec.get('indicator'), rec.get('type'))
                if key not in seen:
                    seen.add(key)
                    unique.append(rec)
            if unique:
                out_path.write_text(json.dumps(unique, ensure_ascii=False, indent=2))
                cnt = len(unique)
                summary['total'] += cnt
                summary['by_source'][prefix] = summary['by_source'].get(prefix, 0) + cnt
                logger.info(f"Wrote {cnt} indicators to {out_path.name}")
            else:
                logger.info(f"No new indicators in {path.name}")
        except Exception:
            logger.exception(f"Failed to normalize {path.name}")

    logger.info(f"Normalization complete: {summary['total']} indicators across {len(summary['by_source'])} sources")


if __name__ == '__main__':
    # Allow quick local run that processes all files in feeds dir
    normalize_all()