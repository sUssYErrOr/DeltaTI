import os
import io
import re
import logging
import asyncio
import aiohttp
import hashlib
import time
import zipfile
import gzip
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from collections import defaultdict
from requests.exceptions import HTTPError, RequestException
from utils.config_utils import load_config, ConfigLoadError
from utils.file_utils import save_to_file
from utils.env_utils import get_otx_key

# Logger setup
logger = logging.getLogger(__name__)

# Configuration
@dataclass
class FeedConfig:
    """Configuration for feed fetching"""
    max_concurrent_requests: int = 5
    request_timeout: int = 30
    retry_attempts: int = 3
    retry_backoff: float = 2.0
    cache_dir: Path = Path("./cache")
    rate_limit_delay: float = 0.5

# Load configuration once
try:
    cfg = load_config()
    PS = cfg.get("phishstats", {})
    BASE_URL = PS.get("base_url", "https://api.phishstats.info/api/phishing")
    LIMIT = PS.get("limit", 100)
    PAGES = PS.get("pages", 3)
    QUERIES = PS.get("queries", [])
    feed_config = FeedConfig()
except (FileNotFoundError, ConfigLoadError) as e:
    logger.critical(f"Configuration loading failed: {e}")
    raise SystemExit(1)

# Compiled regex patterns
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
URL_RE = re.compile(r"https?://[^\s'\",]+")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)

# Cache for deduplication
class ContentCache:
    """Simple content hash cache for deduplication"""
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(exist_ok=True)
        self.memory_cache: Dict[str, str] = {}
        self.load_cache()
    
    def load_cache(self):
        """Load cache index from disk"""
        cache_file = self.cache_dir / "cache_index.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    self.memory_cache = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load cache index: {e}")
    
    def save_cache(self):
        """Save cache index to disk"""
        cache_file = self.cache_dir / "cache_index.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(self.memory_cache, f)
        except Exception as e:
            logger.warning(f"Failed to save cache index: {e}")
    
    def get_content_hash(self, content: bytes) -> str:
        """Get SHA256 hash of content"""
        return hashlib.sha256(content).hexdigest()
    
    def is_new_content(self, feed_name: str, content: bytes) -> bool:
        """Check if content is new based on hash"""
        content_hash = self.get_content_hash(content)
        last_hash = self.memory_cache.get(feed_name)
        
        if last_hash == content_hash:
            return False
        
        self.memory_cache[feed_name] = content_hash
        self.save_cache()
        return True

# Initialize cache
content_cache = ContentCache(feed_config.cache_dir)

# Rate limiter
class RateLimiter:
    """Simple rate limiter for API requests"""
    def __init__(self, delay: float = 0.5):
        self.delay = delay
        self.last_request: Dict[str, float] = defaultdict(float)
        self._lock = asyncio.Lock()
    
    async def wait_if_needed(self, domain: str):
        """Wait if necessary to respect rate limits"""
        async with self._lock:
            now = time.time()
            last = self.last_request[domain]
            if last > 0:
                elapsed = now - last
                if elapsed < self.delay:
                    await asyncio.sleep(self.delay - elapsed)
            self.last_request[domain] = time.time()

rate_limiter = RateLimiter(feed_config.rate_limit_delay)

# Async HTTP client
async def create_session() -> aiohttp.ClientSession:
    """Create optimized aiohttp session"""
    connector = aiohttp.TCPConnector(
        limit=feed_config.max_concurrent_requests,
        ttl_dns_cache=300,
        enable_cleanup_closed=True
    )
    
    timeout = aiohttp.ClientTimeout(
        total=feed_config.request_timeout,
        connect=10,
        sock_read=10
    )
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    return aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=headers
    )

async def fetch_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    headers: Optional[Dict] = None,
    retries: int = 3,
    backoff: float = 2.0
) -> aiohttp.ClientResponse:
    """Fetch URL with retry logic"""
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    
    # Apply rate limiting
    await rate_limiter.wait_if_needed(domain)
    
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status >= 400 and resp.status < 500 and resp.status != 429:
                    logger.error(f"[fetch] {url} returned {resp.status}")
                    resp.raise_for_status()
                
                if resp.status == 200:
                    return await resp.read()
                
                resp.raise_for_status()
                
        except aiohttp.ClientError as e:
            last_error = e
            if attempt < retries:
                wait_time = backoff ** (attempt - 1)
                logger.warning(f"[Retry] {url} attempt {attempt} failed. Retrying in {wait_time}s...")
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"[Retry] All {retries} attempts failed for {url}")
    
    raise last_error

# Optimized feed fetchers
async def fetch_urlhaus_csv_online(session: aiohttp.ClientSession):
    """Fetch URLhaus CSV data"""
    logger.info("[URLhaus] Starting fetch...")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        content = await fetch_with_retry(session, url)
        
        # Check if content is new
        if not content_cache.is_new_content("urlhaus", content):
            logger.info("[URLhaus] Content unchanged, skipping save")
            return
        
        save_to_file("urlhaus_online", content.decode('utf-8'), "csv")
        logger.info("[URLhaus] Fetch completed successfully.")
    except Exception as e:
        logger.exception(f"[URLhaus] Fetch failed: {e}")

async def fetch_threatfox(session: aiohttp.ClientSession):
    """Fetch ThreatFox ZIP data"""
    logger.info("[ThreatFox] Starting ZIP fetch...")
    url = "https://threatfox.abuse.ch/export/csv/full/"
    try:
        content = await fetch_with_retry(session, url)
        
        # Process ZIP in memory
        with zipfile.ZipFile(io.BytesIO(content), 'r') as zip_ref:
            file_list = zip_ref.namelist()
            if not file_list:
                logger.error("[ThreatFox] ZIP archive is empty.")
                return
            
            csv_name = file_list[0]
            with zip_ref.open(csv_name) as csv_file:
                csv_data = csv_file.read()
                
                # Check if content is new
                if not content_cache.is_new_content("threatfox", csv_data):
                    logger.info("[ThreatFox] Content unchanged, skipping save")
                    return
                
                save_to_file("threatfox_full", csv_data.decode("utf-8"), "csv")
                logger.info(f"[ThreatFox] CSV extracted and saved")
    except Exception as e:
        logger.exception(f"[ThreatFox] Fetch failed: {e}")

async def fetch_phishtank(session: aiohttp.ClientSession):
    """Fetch PhishTank gzipped data"""
    logger.info("[PhishTank] Starting fetch...")
    url = "http://data.phishtank.com/data/online-valid.csv.gz"
    try:
        content = await fetch_with_retry(session, url)
        
        # Decompress gzip data
        with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz:
            text = gz.read()
            
            # Check if content is new
            if not content_cache.is_new_content("phishtank", text):
                logger.info("[PhishTank] Content unchanged, skipping save")
                return
            
            decoded_text = text.decode("utf-8")
            lines = decoded_text.strip().split('\n')
            
            if len(lines) < 2:
                logger.error("[PhishTank] CSV appears empty or missing data rows.")
                return
            
            save_to_file("phishtank", decoded_text, "csv")
            logger.info("[PhishTank] Fetch completed successfully.")
    except Exception as e:
        logger.exception(f"[PhishTank] Fetch failed: {e}")

async def fetch_phishstats(session: aiohttp.ClientSession):
    """Fetch PhishStats data with deduplication"""
    seen_ids: Set[int] = set()
    all_entries = []
    
    # Create tasks for all queries and pages
    tasks = []
    for q in QUERIES:
        name = q.get("name", "general")
        filt = q.get("filter", "")
        
        for page in range(1, PAGES + 1):
            url = (
                f"{BASE_URL}?{filt}&_page={page}&_perPage={LIMIT}" if filt
                else f"{BASE_URL}?_page={page}&_perPage={LIMIT}"
            )
            tasks.append(fetch_phishstats_page(session, url, name, page, seen_ids))
    
    # Execute all tasks concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Collect all entries
    for result in results:
        if isinstance(result, list):
            all_entries.extend(result)
    
    # Save deduplicated entries
    if all_entries:
        save_to_file("phishstats_all", all_entries, "json")
        logger.info(f"[PhishStats] Saved {len(all_entries)} total unique entries")

# ... (continuing from where I left off)

async def fetch_phishstats_page(
    session: aiohttp.ClientSession,
    url: str,
    name: str,
    page: int,
    seen_ids: Set[int]
) -> List[Dict]:
    """Fetch single PhishStats page"""
    logger.info(f"[PhishStats] Fetching '{name}' - page {page}")
    try:
        content = await fetch_with_retry(session, url)
        data = json.loads(content)
        
        # Filter unique entries by ID (thread-safe with asyncio)
        new_entries = []
        for entry in data:
            pid = entry.get("id")
            if pid and pid not in seen_ids:
                seen_ids.add(pid)
                new_entries.append(entry)
        
        logger.info(f"[PhishStats] Page {page} returned {len(new_entries)} unique entries")
        return new_entries
        
    except Exception as e:
        logger.exception(f"[PhishStats] Failed for '{name}', page {page}: {e}")
        return []

# Simple feed fetchers (converted to async)
async def fetch_simple_text_feed(session: aiohttp.ClientSession, name: str, url: str, file_ext: str = "txt"):
    """Generic async fetcher for simple text feeds"""
    logger.info(f"[{name}] Starting fetch...")
    try:
        content = await fetch_with_retry(session, url)
        
        # Check if content is new
        if not content_cache.is_new_content(name.lower(), content):
            logger.info(f"[{name}] Content unchanged, skipping save")
            return
        
        save_to_file(name.lower(), content.decode('utf-8'), file_ext)
        logger.info(f"[{name}] Fetch completed successfully.")
    except Exception as e:
        logger.exception(f"[{name}] Fetch failed: {e}")

async def fetch_otx(session: aiohttp.ClientSession):
    """Fetch OTX data with API key"""
    logger.info("[OTX] Starting fetch...")
    api_key = get_otx_key()
    if not api_key:
        logger.error("[OTX] No API key available")
        return
        
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1"
    headers = {"X-OTX-API-KEY": api_key}
    
    try:
        content = await fetch_with_retry(session, url, headers=headers)
        data = json.loads(content)
        results = data.get("results", [])
        
        # Process pulses concurrently
        tasks = []
        for pulse in results:
            pulse_id = pulse.get("id", "unknown")
            tasks.append(save_pulse_async(f"otx_pulse_{pulse_id}", pulse))
        
        await asyncio.gather(*tasks)
        logger.info(f"[OTX] Fetched {len(results)} pulses successfully.")
    except Exception as e:
        logger.exception(f"[OTX] Fetch failed: {e}")

async def save_pulse_async(filename: str, pulse_data: Dict):
    """Save pulse data asynchronously"""
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        await loop.run_in_executor(executor, save_to_file, filename, pulse_data, "json")

@lru_cache(maxsize=1000)
def extract_iocs_from_text_blob(text: str) -> Tuple[str, ...]:
    """Find likely IOCs in a text blob (cached for performance)"""
    found = set()
    for regex in (URL_RE, IP_RE, DOMAIN_RE):
        found.update(m.strip() for m in regex.findall(text))
    return tuple(sorted(found))

async def fetch_dshield_feeds(session: aiohttp.ClientSession):
    """Fetch both DShield feeds efficiently"""
    urls = [
        ("openioc", "https://www.dshield.org/api/openiocsources/"),
        ("threatfeeds", "https://www.dshield.org/api/threatfeeds/")
    ]
    
    tasks = [fetch_dshield_feed(session, name, url) for name, url in urls]
    await asyncio.gather(*tasks)

async def fetch_dshield_feed(session: aiohttp.ClientSession, feed_name: str, url: str):
    """Fetch individual DShield feed"""
    logger.info(f"[DShield] Starting fetch ({feed_name})...")
    try:
        content = await fetch_with_retry(session, url)
        
        # Check if content is new
        if not content_cache.is_new_content(f"dshield_{feed_name}", content):
            logger.info(f"[DShield] {feed_name} content unchanged, skipping save")
            return
        
        # Process content efficiently
        iocs = await process_dshield_content(content)
        
        if iocs:
            save_to_file(f"dshield_{feed_name}", "\n".join(iocs), "txt")
            logger.info(f"[DShield] Saved {len(iocs)} IOCs from {feed_name}")
        else:
            logger.warning(f"[DShield] No IOCs extracted from {feed_name}")
            
    except Exception as e:
        logger.exception(f"[DShield] {feed_name} fetch failed: {e}")

async def process_dshield_content(content: bytes) -> List[str]:
    """Process DShield content to extract IOCs"""
    try:
        text = content.decode("utf-8", errors="ignore")
        
        # Check if it's XML content
        if b"<?xml" in content[:200].lower():
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                iocs = await loop.run_in_executor(executor, parse_xml_content, text)
        else:
            iocs = extract_iocs_from_text_blob(text)
        
        return list(iocs)
    except Exception as e:
        logger.error(f"[DShield] Content processing failed: {e}")
        return []

def parse_xml_content(text: str) -> List[str]:
    """Parse XML content and extract IOCs"""
    try:
        root = ET.fromstring(text)
        blob_parts = []
        
        for elem in root.iter():
            if elem.text:
                blob_parts.append(elem.text)
            blob_parts.extend(elem.attrib.values())
        
        blob_text = "\n".join(blob_parts)
        return list(extract_iocs_from_text_blob(blob_text))
    except ET.ParseError as e:
        logger.error(f"XML parse error: {e}")
        return []

async def fetch_bazaar_feeds(session: aiohttp.ClientSession):
    """Fetch Bazaar feeds concurrently"""
    tasks = [
        fetch_bazaar_recent_csv(session),
        fetch_bazaar_yara_stats(session)
    ]
    await asyncio.gather(*tasks)

async def fetch_bazaar_recent_csv(session: aiohttp.ClientSession):
    """Fetch Bazaar recent CSV"""
    await fetch_simple_text_feed(session, "Bazaar Recent", 
                                "https://bazaar.abuse.ch/export/csv/recent/", "csv")

async def fetch_bazaar_yara_stats(session: aiohttp.ClientSession):
    """Fetch Bazaar YARA stats JSON"""
    logger.info("[Bazaar] Starting fetch: yara-stats (JSON)")
    url = "https://bazaar.abuse.ch/export/json/yara-stats/"
    try:
        content = await fetch_with_retry(session, url)
        data = json.loads(content)
        save_to_file("bazaar_yara_stats", data, "json")
        logger.info("[Bazaar] Saved yara-stats JSON")
    except Exception as e:
        logger.exception(f"[Bazaar] yara-stats fetch failed: {e}")

async def fetch_malshare_list(session: aiohttp.ClientSession):
    """Fetch MalShare list"""
    logger.info("[MalShare] Starting fetch: getlist")
    api_key = os.getenv("MALSHARE_API_KEY")
    if not api_key:
        logger.error("[MalShare] No API key set in MALSHARE_API_KEY")
        return
        
    url = f"https://malshare.com/api.php?api_key={api_key}&action=getlist"
    try:
        content = await fetch_with_retry(session, url)
        
        try:
            data = json.loads(content)
            save_to_file("malshare_getlist", data, "json")
        except json.JSONDecodeError:
            save_to_file("malshare_getlist", content.decode('utf-8'), "txt")
            
        logger.info("[MalShare] Saved getlist")
    except Exception as e:
        logger.exception(f"[MalShare] fetch failed: {e}")

# Async feed registry with priorities
@dataclass
class FeedJob:
    name: str
    func: callable
    priority: int = 1  # Lower number = higher priority
    dependencies: List[str] = None

FEED_JOBS = [
    FeedJob("urlhaus", fetch_urlhaus_csv_online, 1),
    FeedJob("threatfox", fetch_threatfox, 1),
    FeedJob("phishtank", fetch_phishtank, 1),
    FeedJob("feodo", lambda s: fetch_simple_text_feed(s, "Feodo", 
           "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", "txt"), 1),
    FeedJob("spamhaus", lambda s: fetch_simple_text_feed(s, "Spamhaus",
           "https://www.spamhaus.org/drop/drop.txt", "txt"), 1),
    FeedJob("emerging_threats", lambda s: fetch_simple_text_feed(s, "Emerging Threats",
           "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "txt"), 1),
    FeedJob("ciarmy", lambda s: fetch_simple_text_feed(s, "CI Army",
           "https://www.ciarmy.com/list/ci-badguys.txt", "txt"), 2),
    FeedJob("phishstats", fetch_phishstats, 2),
    FeedJob("otx", fetch_otx, 2),
    FeedJob("dshield", fetch_dshield_feeds, 2),
    FeedJob("bazaar", fetch_bazaar_feeds, 3),
    FeedJob("malshare", fetch_malshare_list, 3),
]

class FeedFetcher:
    """Main feed fetcher coordinator"""
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(feed_config.max_concurrent_requests)
    
    async def __aenter__(self):
        self.session = await create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def run_job(self, job: FeedJob):
        """Run a single feed job with semaphore control"""
        async with self.semaphore:
            start_time = time.time()
            try:
                await job.func(self.session)
                elapsed = time.time() - start_time
                logger.info(f"[{job.name}] Completed in {elapsed:.2f}s")
            except Exception as e:
                logger.exception(f"[{job.name}] Job failed: {e}")
    
    async def run_all_feeds(self, priority_filter: Optional[int] = None):
        """Run all feed jobs, optionally filtered by priority"""
        jobs = FEED_JOBS
        if priority_filter:
            jobs = [job for job in jobs if job.priority <= priority_filter]
        
        # Sort by priority
        jobs.sort(key=lambda x: x.priority)
        
        logger.info(f"Starting {len(jobs)} feed jobs...")
        start_time = time.time()
        
        # Create tasks for all jobs
        tasks = [self.run_job(job) for job in jobs]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        total_time = time.time() - start_time
        logger.info(f"All feeds completed in {total_time:.2f}s")

# Main execution functions
async def fetch_all_feeds(priority_filter: Optional[int] = None):
    """Main async function to fetch all feeds"""
    async with FeedFetcher() as fetcher:
        await fetcher.run_all_feeds(priority_filter)

def run_feed_collection(priority_filter: Optional[int] = None):
    """Synchronous entry point for feed collection"""
    try:
        asyncio.run(fetch_all_feeds(priority_filter))
    except KeyboardInterrupt:
        logger.info("Feed collection interrupted by user")
    except Exception as e:
        logger.exception(f"Feed collection failed: {e}")

# Performance monitoring
class PerformanceMonitor:
    """Simple performance monitoring"""
    
    def __init__(self):
        self.stats = defaultdict(list)
    
    def record_timing(self, operation: str, duration: float):
        self.stats[operation].append(duration)
    
    def get_summary(self) -> Dict[str, Dict[str, float]]:
        summary = {}
        for op, times in self.stats.items():
            summary[op] = {
                'count': len(times),
                'total': sum(times),
                'avg': sum(times) / len(times) if times else 0,
                'min': min(times) if times else 0,
                'max': max(times) if times else 0
            }
        return summary

# Usage example
if __name__ == "__main__":
    # Run all feeds
    run_feed_collection()