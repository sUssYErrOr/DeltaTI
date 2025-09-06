#!/usr/bin/env python3
"""
main.py - DeltaTI scheduler/runner (async-optimized)

Key improvements:
- Integrated with async feed fetcher system
- Maintains existing scheduling and normalization logic
- Added performance monitoring and better error handling
- Supports priority-based feed execution
- Maintains backward compatibility with existing normalizer
"""
import sys
import time
import logging
import inspect
import asyncio
from pathlib import Path
from typing import Callable, List, Set, Optional
import schedule
from datetime import datetime, timedelta

# --- project root and imports for your package ---
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Import the new async fetcher system
from collectors.feeds.fetchers import (
    FeedFetcher, FEED_JOBS, FeedJob, 
    fetch_all_feeds, run_feed_collection,
    PerformanceMonitor
)
from Normalizer.normalizer import normalize_all
from collectors.utils.file_utils import ensure_data_dir

# --- logger setup (single handler; avoid duplicate prints) ---
logger = logging.getLogger("DeltaTI")
logger.setLevel(logging.INFO)
logger.propagate = False

# Ensure only one handler is attached to avoid duplicate messages
if not logger.handlers:
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))
    logger.addHandler(sh)

# --- Constants / paths ---
SCHEDULE_TIME = "22:00"       # daily trigger time
SLEEP_INTERVAL = 30           # seconds between main-loop checks
HEARTBEAT_INTERVAL = 7200     # seconds (2 hours)

FEEDS_DIR = project_root / "collectors" / "data" / "feeds"
NORMALIZED_DIR = project_root / "Normalizer" / "normalized_data"

# ensure directories exist
FEEDS_DIR.mkdir(parents=True, exist_ok=True)
NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)

# Performance monitoring
perf_monitor = PerformanceMonitor()

# --- Helpers ---
def list_raw_files() -> Set[str]:
    """
    Return set of raw filenames in FEEDS_DIR (skip files whose names
    indicate they are normalized outputs).
    """
    files = set()
    for p in FEEDS_DIR.iterdir():
        if not p.is_file():
            continue
        # skip normalized outputs (normalized_*.json) and hidden files
        if p.name.startswith("normalized_") or p.name.startswith("."):
            continue
        files.add(p.name)
    return files


def already_normalized_for(stem: str) -> bool:
    """
    Return True if normalized_{stem}.json already exists in normalized dir.
    """
    return (NORMALIZED_DIR / f"normalized_{stem}.json").exists()


def _call_normalize(paths: List[Path]) -> None:
    """
    Call normalize_all either with a list of Path objects (if supported)
    or with no args (fallback).
    """
    start_time = time.time()
    try:
        sig = inspect.signature(normalize_all)
        if len(sig.parameters) == 0:
            logger.debug("[Normalize] normalize_all() expects no args — calling without args")
            normalize_all()   # type: ignore[arg-type]
        else:
            logger.debug("[Normalize] normalize_all() accepts args — calling with paths")
            normalize_all(paths)  # type: ignore[arg-type]
        
        # Record performance
        duration = time.time() - start_time
        perf_monitor.record_timing("normalize", duration)
        logger.info(f"[Normalize] Completed in {duration:.2f}s")
        
    except Exception:
        # best-effort fallback to no-arg call
        try:
            normalize_all()  # type: ignore[arg-type]
        except Exception as e:
            logger.exception(f"[Normalize] normalize_all failed (both arg/no-arg attempts): {e}")
            raise


# --- Core pipeline (updated for async) ---
async def run_async_pipeline(job_names: List[str] = None, priority_filter: Optional[int] = None) -> None:
    """
    Run async fetcher jobs, then normalize newly created files.
    """
    logger.info(f"[Pipeline] Starting async pipeline")
    before = list_raw_files()
    start_time = time.time()

    try:
        if job_names:
            # Run specific jobs
            async with FeedFetcher() as fetcher:
                jobs_to_run = [job for job in FEED_JOBS if job.name in job_names]
                if priority_filter:
                    jobs_to_run = [job for job in jobs_to_run if job.priority <= priority_filter]
                
                tasks = [fetcher.run_job(job) for job in jobs_to_run]
                await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Run all feeds with optional priority filter
            await fetch_all_feeds(priority_filter)
        
        duration = time.time() - start_time
        perf_monitor.record_timing("fetch_all", duration)
        logger.info(f"[Pipeline] Async fetch completed in {duration:.2f}s")
        
    except Exception as e:
        logger.exception(f"[Pipeline] Async fetch failed: {e}")
        return

    # Check what files were created
    after = list_raw_files()
    created = sorted(after - before)  # filenames

    # filter out any created files that already have normalized output
    to_normalize = []
    for fname in created:
        stem = Path(fname).stem
        if already_normalized_for(stem):
            logger.info(f"[Normalize] Skipping {fname} — already normalized (normalized_{stem}.json exists)")
        else:
            to_normalize.append(FEEDS_DIR / fname)

    if not to_normalize:
        logger.info(f"[Pipeline] No new un-normalized files — skipping normalization")
        return

    logger.info(f"[Pipeline] Normalizing {len(to_normalize)} new file(s)")
    try:
        _call_normalize(to_normalize)
        logger.info(f"[Pipeline] Finished normalization")
    except Exception as e:
        logger.exception(f"[Pipeline] Normalization failed: {e}")


def run_pipeline_sync(job_names: List[str] = None, priority_filter: Optional[int] = None) -> None:
    """
    Synchronous wrapper for async pipeline
    """
    try:
        asyncio.run(run_async_pipeline(job_names, priority_filter))
    except Exception as e:
        logger.exception(f"[Pipeline] Pipeline execution failed: {e}")


# --- Individual job runners for backward compatibility ---
def run_individual_job(job_name: str) -> None:
    """
    Run a single job by name (for backward compatibility with scheduler)
    """
    logger.info(f"[Job] Running individual job: {job_name}")
    
    # Map old function names to new job names
    job_mapping = {
        "fetch_urlhaus_csv_online": "urlhaus",
        "fetch_threatfox": "threatfox",
        "fetch_feodo": "feodo",
        "fetch_phishtank": "phishtank",
        "fetch_phishstats": "phishstats",
        "fetch_spamhaus": "spamhaus",
        "fetch_emerging_threats": "emerging_threats",
        "fetch_ciarmy": "ciarmy",
        "fetch_otx": "otx",
        "fetch_dshield_openioc": "dshield",
        "fetch_bazaar_recent_csv": "bazaar",
        "fetch_malshare_list": "malshare",
    }
    
    new_job_name = job_mapping.get(job_name, job_name)
    run_pipeline_sync([new_job_name])


# --- Scheduling (updated for async) ---
def schedule_jobs() -> None:
    """
    Schedule jobs with the cadence you defined:
    - monthly: urlhaus, feodo, ciarmy  (day 1 @ SCHEDULE_TIME)
    - threatfox: every 48 hours
    - others: daily @ SCHEDULE_TIME
    This function clears previous schedules first to avoid duplication.
    """
    logger.info("[Scheduler] Clearing previous schedule entries (if any)")
    schedule.clear()

    logger.info("[Scheduler] Setting up job intervals…")

    def monthly_wrapper(job_names: List[str]):
        def wrapper():
            # run only on day 1 of month
            if time.localtime().tm_mday == 1:
                run_pipeline_sync(job_names)
            else:
                logger.debug(f"[Scheduler] Skipping monthly jobs {job_names} (today != 1)")
        return wrapper

    def daily_wrapper(job_names: List[str]):
        def wrapper():
            run_pipeline_sync(job_names)
        return wrapper

    def priority_wrapper(priority: int):
        def wrapper():
            run_pipeline_sync(priority_filter=priority)
        return wrapper

    # Group jobs by schedule type
    monthly_jobs = ["urlhaus", "feodo", "ciarmy"]
    daily_high_priority = ["phishtank", "spamhaus", "emerging_threats"]
    daily_medium_priority = ["phishstats", "otx", "dshield"]
    daily_low_priority = ["bazaar", "malshare"]

    # Schedule monthly jobs
    schedule.every().day.at(SCHEDULE_TIME).do(monthly_wrapper(monthly_jobs))
    logger.info(f" • Monthly jobs {monthly_jobs}: monthly (day=1 @ {SCHEDULE_TIME})")

    # Schedule ThreatFox every 48 hours
    schedule.every(48).hours.do(daily_wrapper(["threatfox"]))
    logger.info(f" • threatfox: every 48 hours")

    # Schedule daily jobs by priority
    schedule.every().day.at(SCHEDULE_TIME).do(daily_wrapper(daily_high_priority))
    logger.info(f" • High priority jobs {daily_high_priority}: daily @ {SCHEDULE_TIME}")

    # Stagger medium priority jobs 30 minutes later
    medium_time = (datetime.strptime(SCHEDULE_TIME, "%H:%M") + timedelta(minutes=30)).strftime("%H:%M")
    schedule.every().day.at(medium_time).do(daily_wrapper(daily_medium_priority))
    logger.info(f" • Medium priority jobs {daily_medium_priority}: daily @ {medium_time}")

    # Stagger low priority jobs 1 hour later
    low_time = (datetime.strptime(SCHEDULE_TIME, "%H:%M") + timedelta(hours=1)).strftime("%H:%M")
    schedule.every().day.at(low_time).do(daily_wrapper(daily_low_priority))
    logger.info(f" • Low priority jobs {daily_low_priority}: daily @ {low_time}")

    logger.info("[Scheduler] Job scheduling complete.")


def initial_run() -> None:
    """
    Run one fetch+normalize for every feed at startup.
    Run high priority feeds first, then others.
    """
    logger.info("[Startup] Running initial collection + normalization for all feeds…")
    
    # Run high priority feeds first
    logger.info("[Startup] Running high priority feeds (priority 1)")
    run_pipeline_sync(priority_filter=1)
    
    # Brief pause between priority levels
    time.sleep(5)
    
    # Run medium priority feeds
    logger.info("[Startup] Running medium priority feeds (priority 2)")
    run_pipeline_sync(priority_filter=2)
    
    # Brief pause
    time.sleep(5)
    
    # Run low priority feeds
    logger.info("[Startup] Running low priority feeds (priority 3)")
    run_pipeline_sync(priority_filter=3)
    
    # Log performance summary
    summary = perf_monitor.get_summary()
    if summary:
        logger.info("[Startup] Performance Summary:")
        for operation, stats in summary.items():
            logger.info(f"  {operation}: {stats['count']} runs, avg {stats['avg']:.2f}s, total {stats['total']:.2f}s")


def run_scheduler() -> None:
    """
    Main loop: run pending scheduled jobs and emit heartbeat every HEARTBEAT_INTERVAL.
    """
    logger.info("[Runtime] Scheduler started. Waiting for jobs…")
    last_heartbeat = time.time()

    try:
        while True:
            schedule.run_pending()
            
            # Emit heartbeat with performance stats
            if time.time() - last_heartbeat >= HEARTBEAT_INTERVAL:
                summary = perf_monitor.get_summary()
                total_ops = sum(stats['count'] for stats in summary.values()) if summary else 0
                logger.info(f"[Heartbeat] Scheduler alive — {total_ops} operations completed since startup")
                last_heartbeat = time.time()
            
            time.sleep(SLEEP_INTERVAL)
            
    except KeyboardInterrupt:
        logger.info("[Shutdown] Interrupted by user")
        # Log final performance summary
        summary = perf_monitor.get_summary()
        if summary:
            logger.info("[Shutdown] Final Performance Summary:")
            for operation, stats in summary.items():
                logger.info(f"  {operation}: {stats['count']} runs, avg {stats['avg']:.2f}s")
                
    except Exception as e:
        logger.exception(f"[Scheduler] Unexpected runtime error: {e}")


# --- CLI support ---
def main() -> None:
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DeltaTI Feed Collector")
    parser.add_argument("--no-initial", action="store_true", 
                       help="Skip initial run of all feeds")
    parser.add_argument("--priority", type=int, choices=[1, 2, 3],
                       help="Run only feeds with specified priority or higher")
    parser.add_argument("--jobs", nargs="+",
                       help="Run specific jobs by name")
    parser.add_argument("--once", action="store_true",
                       help="Run once and exit (don't start scheduler)")
    
    args = parser.parse_args()
    
    logger.info("[Init] DeltaTI starting")
    ensure_data_dir()   # from collectors.utils.file_utils
    
    if args.once:
        # Run once and exit
        if args.jobs:
            run_pipeline_sync(args.jobs, args.priority)
        else:
            run_pipeline_sync(priority_filter=args.priority)
        return
    
    if not args.no_initial:
        initial_run()
    
    schedule_jobs()
    run_scheduler()


if __name__ == "__main__":
    main()