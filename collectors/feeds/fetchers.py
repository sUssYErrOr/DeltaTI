import os
import io
import re
import logging
import base64
import time
import requests
import zipfile
import gzip
import json
import xml.etree.ElementTree as ET
from typing import List
from requests.exceptions import HTTPError, RequestException
from utils.config_utils import load_config, ConfigLoadError
from utils.file_utils import save_to_file
from utils.env_utils import get_otx_key
from datetime import datetime

# Logger setup
logger = logging.getLogger(__name__)
session = requests.Session()

# Load configuration once
try:
    cfg = load_config()
    PS = cfg.get("phishstats", {})
    BASE_URL = PS.get("base_url", "https://api.phishstats.info/api/phishing")
    LIMIT = PS.get("limit", 100)
    PAGES = PS.get("pages", 3)
    QUERIES = PS.get("queries", [])  # List of dicts with 'name' and 'filter'
except (FileNotFoundError, ConfigLoadError) as e:
    logger.critical(f"Configuration loading failed: {e}")
    raise SystemExit(1)

IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
URL_RE = re.compile(r"https?://[^\s'\",]+")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def safe_get(url, headers=None, retries=3, backoff=2):
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    merged_headers = {**default_headers, **(headers or {})}

    for attempt in range(1, retries + 1):
        resp = session.get(url, headers=merged_headers, timeout=30)
        status = resp.status_code

        if 400 <= status < 500 and status != 429:
            logger.error(f"[safe_get] {url} returned {status}: {resp.text[:200]!r}. Skipping retries.")
            resp.raise_for_status()

        try:
            resp.raise_for_status()
            return resp
        except HTTPError:
            if attempt < retries:
                logger.warning(f"[Retry] {url} attempt {attempt} failed: {status}. Retrying in {backoff}s...")
                time.sleep(backoff)
                backoff *= 2
            else:
                logger.error(f"[Retry] All {retries} attempts failed for {url}")
                raise


def fetch_urlhaus_csv_online():
    logger.info("[URLhaus] Starting fetch...") # every Month
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        resp = safe_get(url)
        save_to_file("urlhaus_online", resp.text, "csv")
        logger.info("[URLhaus] Fetch completed successfully.")
    except RequestException:
        logger.exception("[URLhaus] Fetch failed")


def fetch_threatfox(): # every 48 hours
    logger.info("[ThreatFox] Starting ZIP fetch...")
    url = "https://threatfox.abuse.ch/export/csv/full/"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()

        if "application/zip" not in resp.headers.get("Content-Type", ""):
            logger.error(f"[ThreatFox] Unexpected content type: {resp.headers.get('Content-Type')}")
            return

        zip_bytes = io.BytesIO(resp.content)
        with zipfile.ZipFile(zip_bytes, 'r') as zip_ref:
            file_list = zip_ref.namelist()
            if not file_list:
                logger.error("[ThreatFox] ZIP archive is empty.")
                return

            csv_name = file_list[0]
            with zip_ref.open(csv_name) as csv_file:
                csv_data = csv_file.read().decode("utf-8")
            save_to_file("threatfox_full", csv_data, "csv")
            logger.info(f"[ThreatFox] CSV extracted")
    except requests.exceptions.RequestException:
        logger.exception("[ThreatFox] ZIP fetch failed")
    except zipfile.BadZipFile:
        logger.exception("[ThreatFox] Failed to extract ZIP")


def fetch_feodo(): # Every Month
    logger.info("[Feodo] Starting fetch...")
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    try:
        resp = safe_get(url)
        save_to_file("feodo", resp.text, "txt")
        logger.info("[Feodo] Fetch completed successfully.")
    except RequestException:
        logger.exception("[Feodo] Fetch failed")


def fetch_phishtank():
    logger.info("[PhishTank] Starting fetch...")
    url = "http://data.phishtank.com/data/online-valid.csv.gz"
    try:
        resp = safe_get(url)
        if resp.status_code != 200:
            logger.error(f"[PhishTank] Unexpected status code: {resp.status_code}")
            return

        ctype = resp.headers.get("Content-Type", "")
        if "gzip" not in ctype and "application/octet-stream" not in ctype:
            logger.warning(f"[PhishTank] Unexpected Content-Type: {ctype} — proceeding with decompression anyway.")

        with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as gz:
            text = gz.read().decode("utf-8")

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) < 2:
            logger.error("[PhishTank] CSV appears empty or missing data rows.")
            return

        header = lines[0].lower()
        if not header.startswith("phish_id"):
            logger.error(f"[PhishTank] Unexpected CSV header: {lines[0]}")
            return

        save_to_file("phishtank", text, "csv")
        logger.info("[PhishTank] Fetch completed successfully.")
    except RequestException:
        logger.exception("[PhishTank] Fetch failed")
    except (gzip.BadGzipFile, UnicodeDecodeError) as e:
        logger.exception(f"[PhishTank] Decompression or decoding failed: {e}")

def fetch_phishstats():
    seen_ids = set()  # Track unique phishing entry IDs

    for q in QUERIES:
        name = q.get("name", "general")
        filt = q.get("filter", "")
        for page in range(1, PAGES + 1):
            url = (
                f"{BASE_URL}?{filt}&_page={page}&_perPage={LIMIT}" if filt
                else f"{BASE_URL}?_page={page}&_perPage={LIMIT}"
            )
            logger.info(f"[PhishStats] Fetching '{name}' - page {page}")
            try:
                resp = safe_get(url)
                data = resp.json()

                # Filter unique entries by ID
                new_entries = []
                for entry in data:
                    pid = entry.get("id")
                    if pid not in seen_ids:
                        seen_ids.add(pid)
                        new_entries.append(entry)

                if not new_entries:
                    logger.info(f"[PhishStats] All entries already seen for '{name}' - page {page}.")
                    continue

                save_to_file(f"phishstats_{name}_page{page}", new_entries)
                logger.info(f"[PhishStats] Saved {len(new_entries)} new unique entries for '{name}', page {page}")
                time.sleep(1)

            except RequestException:
                logger.exception(f"[PhishStats] Failed for '{name}', page {page}")



def fetch_spamhaus(): # Daily
    logger.info("[Spamhaus] Starting fetch...")
    url = "https://www.spamhaus.org/drop/drop.txt"
    try:
        resp = safe_get(url)
        save_to_file("spamhaus", resp.text, "txt")
        logger.info("[Spamhaus] Fetch completed successfully.")
    except RequestException:
        logger.exception("[Spamhaus] Fetch failed")


def fetch_emerging_threats(): # daily
    logger.info("[Emerging Threats] Starting fetch...")
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    try:
        resp = safe_get(url)
        save_to_file("emerging_threats", resp.text, "txt")
        logger.info("[Emerging Threats] Fetch completed successfully.")
    except RequestException:
        logger.exception("[Emerging Threats] Fetch failed")


def fetch_ciarmy(): # Monthly
    logger.info("[CI Army] Starting fetch...")
    url = "https://www.ciarmy.com/list/ci-badguys.txt"
    try:
        resp = safe_get(url)
        save_to_file("ciarmy", resp.text, "txt")
        logger.info("[CI Army] Fetch completed successfully.")
    except RequestException:
        logger.exception("[CI Army] Fetch failed")


def fetch_otx(): # Every 24 hours and make check if the data is the same do not save anything
    logger.info("[OTX] Starting fetch...")
    api_key = get_otx_key()
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        resp = safe_get(url, headers=headers)
        results = resp.json().get("results", [])
        for pulse in results:
            pulse_id = pulse.get("id", "unknown")
            save_to_file(f"otx_pulse_{pulse_id}", pulse)
        logger.info(f"[OTX] Fetched {len(results)} pulses successfully.")
    except RequestException:
        logger.exception("[OTX] Fetch failed")

def extract_iocs_from_text_blob(text: str) -> List[str]:
    """Find likely IOCs in a text blob (IPs, URLs, domains)."""
    found = set()
    for regex in (URL_RE, IP_RE, DOMAIN_RE):
        for m in regex.findall(text):
            found.add(m.strip())
    return sorted(found)

def fetch_dshield_openioc():
    logger.info("[DShield] Starting fetch...")
    url = "https://www.dshield.org/api/openiocsources/"  # adjust to real endpoint if different
    try:
        resp = safe_get(url)
    except RequestException:
        logger.exception("[DShield] HTTP error")
        return

    ctype = (resp.headers.get("Content-Type") or "").lower()
    logger.info(f"[DShield] Content-Type detected: {ctype}")

    body = resp.content  # bytes
    try:
        if b"<?xml" in body[:200].lower() or "xml" in ctype:
            # Parse XML properly
            # decode to str for ElementTree
            text = body.decode("utf-8", errors="ignore")
            root = ET.fromstring(text)
            # Walk tree and collect text from elements/attributes
            blob_parts = []
            for elem in root.iter():
                if elem.text:
                    blob_parts.append(elem.text)
                # also check attributes
                for v in elem.attrib.values():
                    blob_parts.append(v)
            blob_text = "\n".join(blob_parts)
            iocs = extract_iocs_from_text_blob(blob_text)
            logger.info(f"[DShield] Extracted {len(iocs)} IOCs from XML")
            if iocs:
                # Save as plain text, one IOC per line so normalizer can consume
                save_to_file("dshield_openioc", "\n".join(iocs), "txt")
                logger.info("[DShield] Saved parsed IOCs to feeds")
            else:
                logger.warning("[DShield] No IOCs extracted from XML payload")
        else:
            # fallback: treat as text and extract IOCs
            text = body.decode("utf-8", errors="ignore")
            iocs = extract_iocs_from_text_blob(text)
            logger.info(f"[DShield] Content-Type not XML but parsed {len(iocs)} IOCs")
            if iocs:
                save_to_file("dshield_openioc", "\n".join(iocs), "txt")
                logger.info("[DShield] Saved fallback-parsed IOCs to feeds")
            else:
                logger.warning("[DShield] Fallback extraction found no IOCs")
    except ET.ParseError as e:
        logger.exception(f"[DShield] XML parse error: {e}")
    except Exception:
        logger.exception("[DShield] Unexpected error while parsing")


    logger.info("[DShield] Starting fetch (threatfeeds)…")
    url = "https://www.dshield.org/api/threatfeeds/"
    try:
        resp = safe_get(url)
    except RequestException:
        logger.exception("[DShield] HTTP error (threatfeeds)")
        return

    ctype = (resp.headers.get("Content-Type") or "").lower()
    logger.info(f"[DShield] Content-Type detected: {ctype}")

    body = resp.content  # bytes
    try:
        if b"<?xml" in body[:200].lower() or "xml" in ctype:
            # Decode to str for XML parser
            text = body.decode("utf-8", errors="ignore")
            root = ET.fromstring(text)

            # Walk XML tree → gather text and attributes
            blob_parts = []
            for elem in root.iter():
                if elem.text:
                    blob_parts.append(elem.text)
                for v in elem.attrib.values():
                    blob_parts.append(v)

            blob_text = "\n".join(blob_parts)
            iocs = extract_iocs_from_text_blob(blob_text)

            logger.info(f"[DShield] Extracted {len(iocs)} IOCs from threatfeeds XML")
            if iocs:
                save_to_file("dshield_threatfeeds", "\n".join(iocs), "txt")
                logger.info("[DShield] Saved parsed IOCs to feeds")
            else:
                logger.warning("[DShield] No IOCs found in threatfeeds XML")
        else:
            # fallback: plain text parsing
            text = body.decode("utf-8", errors="ignore")
            iocs = extract_iocs_from_text_blob(text)
            logger.info(f"[DShield] Non-XML content, extracted {len(iocs)} IOCs")
            if iocs:
                save_to_file("dshield_threatfeeds", "\n".join(iocs), "txt")
                logger.info("[DShield] Saved fallback-parsed IOCs to feeds")
            else:
                logger.warning("[DShield] No IOCs found in fallback text")
    except ET.ParseError as e:
        logger.exception(f"[DShield] XML parse error: {e}")
    except Exception:
        logger.exception("[DShield] Unexpected error while parsing threatfeeds")

def fetch_bazaar_recent_csv():
    logger.info("[Bazaar] Starting fetch: recent CSV")
    url = "https://bazaar.abuse.ch/export/csv/recent/"
    try:
        resp = safe_get(url)
        text = resp.text
        save_to_file("bazaar_recent", text, "csv")
        logger.info("[Bazaar] Saved recent CSV")
    except RequestException:
        logger.exception("[Bazaar] fetch failed")

def fetch_bazaar_yara_stats():
    logger.info("[Bazaar] Starting fetch: yara-stats (JSON)")
    url = "https://bazaar.abuse.ch/export/json/yara-stats/"
    try:
        resp = safe_get(url)
        data = resp.json()
        # Save full JSON for records & further analysis
        save_to_file("bazaar_yara_stats", data, "json")
        logger.info("[Bazaar] Saved yara-stats JSON")
    except RequestException:
        logger.exception("[Bazaar] fetch failed")


def fetch_malshare_list():
    logger.info("[MalShare] Starting fetch: getlist")
    api_key = os.getenv("MALSHARE_API_KEY")  # ensure you set it
    if not api_key:
        logger.error("[MalShare] No API key set in MALSHARE_API_KEY")
        return
    url = f"https://malshare.com/api.php?api_key={api_key}&action=getlist"
    try:
        resp = safe_get(url)
        # Malshare sometimes returns text lines or JSON
        try:
            data = resp.json()
            save_to_file("malshare_getlist", data, "json")
        except ValueError:
            # fallback to plain text listing
            save_to_file("malshare_getlist", resp.text, "txt")
        logger.info("[MalShare] Saved getlist")
    except RequestException:
        logger.exception("[MalShare] fetch failed")



# Registry of all fetcher jobs
FEED_REGISTRY = [
    fetch_urlhaus_csv_online,
    fetch_threatfox,
    fetch_feodo,
    fetch_phishtank,
    fetch_phishstats,
    fetch_spamhaus,
    fetch_emerging_threats,
    fetch_ciarmy,
    fetch_otx,
    fetch_bazaar_yara_stats,
    fetch_bazaar_recent_csv,
    fetch_dshield_openioc,
    fetch_malshare_list,
]
