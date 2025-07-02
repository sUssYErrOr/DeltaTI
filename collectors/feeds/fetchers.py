import os
import io
import logging
import base64
import time
import requests
import zipfile
import gzip
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


def safe_get(url, headers=None, retries=3, backoff=2):
    """
    GET with retries and exponential backoff on 5xx and 429 errors.
    Skip retries for other 4xx errors.
    """
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
    logger.info("[URLhaus] Starting fetch...")
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    try:
        resp = safe_get(url)
        save_to_file("urlhaus_online", resp.text, "csv")
        logger.info("[URLhaus] Fetch completed successfully.")
    except RequestException:
        logger.exception("[URLhaus] Fetch failed")


def fetch_threatfox():
    logger.info("[ThreatFox] Starting ZIP fetch...")

    url = "https://threatfox.abuse.ch/export/csv/full/"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()

        if "application/zip" not in resp.headers.get("Content-Type", ""):
            logger.error(f"[ThreatFox] Unexpected content type: {resp.headers.get('Content-Type')}")
            return

        # Read ZIP into memory
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

def fetch_feodo():
    logger.info("[Feodo] Starting fetch...")
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"
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
    for q in QUERIES:
        name = q.get("name", "general")
        filt = q.get("filter", "")
        for page in range(PAGES):
            start = page * LIMIT
            url = (
                f"{BASE_URL}?{filt}&_start={start}&_limit={LIMIT}" if filt
                else f"{BASE_URL}?_start={start}&_limit={LIMIT}"
            )
            logger.info(f"[PhishStats] Starting fetch for '{name}', page {page}")
            try:
                resp = safe_get(url)
                data = resp.json()
                if not data:
                    logger.info(f"[PhishStats] No more data for '{name}' at page {page}")
                    break
                save_to_file(f"phishstats_{name}", data)
                logger.info(f"[PhishStats] Fetched and saved '{name}', page {page}")
            except RequestException:
                logger.exception(f"[PhishStats] Fetch failed for '{name}', page {page}")


def fetch_spamhaus():
    logger.info("[Spamhaus] Starting fetch...")
    url = "https://www.spamhaus.org/drop/drop.txt"
    try:
        resp = safe_get(url)
        save_to_file("spamhaus", resp.text, "txt")
        logger.info("[Spamhaus] Fetch completed successfully.")
    except RequestException:
        logger.exception("[Spamhaus] Fetch failed")


def fetch_emerging_threats():
    logger.info("[Emerging Threats] Starting fetch...")
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    try:
        resp = safe_get(url)
        save_to_file("emerging_threats", resp.text, "txt")
        logger.info("[Emerging Threats] Fetch completed successfully.")
    except RequestException:
        logger.exception("[Emerging Threats] Fetch failed")


def fetch_ciarmy():
    logger.info("[CI Army] Starting fetch...")
    url = "https://www.ciarmy.com/list/ci-badguys.txt"
    try:
        resp = safe_get(url)
        save_to_file("ciarmy", resp.text, "txt")
        logger.info("[CI Army] Fetch completed successfully.")
    except RequestException:
        logger.exception("[CI Army] Fetch failed")

'''
def fetch_abuseipdb(): # NEED SUBSCRIPTION
    logger.info("[AbuseIPDB] Starting fetch...")
    api_key = os.getenv("ABUSEIPDB_KEY")
    if not api_key:
        logger.error("[AbuseIPDB] No API key found; skipping.")
        return

    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    try:
        resp = session.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        save_to_file("abuseipdb", data)
        logger.info(f"[AbuseIPDB] Fetched {len(data)} entries.")
    except RequestException:
        logger.exception("[AbuseIPDB] Fetch failed")
'''

def fetch_otx():
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
    #fetch_abuseipdb,
    fetch_otx,
]