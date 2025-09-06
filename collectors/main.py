#!/usr/bin/env python3
"""
main.py - DeltaTI scheduler/runner (robustified)

Key improvements:
- avoids duplicate scheduling/log lines (schedule.clear + single logger handler),
- checks/creates feed & normalized directories,
- detects whether normalize_all accepts a list of Paths and calls it accordingly,
- skips re-normalizing files for which normalized output already exists,
- clearer logging and small helper functions.
"""
import sys
import time
import logging
import inspect
from pathlib import Path
from typing import Callable, List, Set
import schedule

# --- project root and imports for your package ---
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from collectors.feeds.fetchers import FEED_REGISTRY
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
    try:
        sig = inspect.signature(normalize_all)
        if len(sig.parameters) == 0:
            logger.debug("[Normalize] normalize_all() expects no args — calling without args")
            normalize_all()   # type: ignore[arg-type]
        else:
            logger.debug("[Normalize] normalize_all() accepts args — calling with paths")
            normalize_all(paths)  # type: ignore[arg-type]
    except Exception:
        # best-effort fallback to no-arg call
        try:
            normalize_all()  # type: ignore[arg-type]
        except Exception as e:
            logger.exception(f"[Normalize] normalize_all failed (both arg/no-arg attempts): {e}")
            raise


# --- Core pipeline ---
def run_pipeline(job_name: str) -> None:
    """
    Run one fetcher job, then normalize newly created files (skip already-normalized).
    """
    job = next((j for j in FEED_REGISTRY if j.__name__ == job_name), None)
    if not job:
        logger.error(f"[Error] No such job in FEED_REGISTRY: {job_name}")
        return

    logger.info(f"[Fetch] Starting {job_name}")
    before = list_raw_files()

    try:
        job()
        logger.info(f"[Fetch] Completed {job_name}")
    except Exception as e:
        logger.exception(f"[Fetch] {job_name} failed: {e}")
        return

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
        logger.info(f"[Normalize] No new un-normalized files from {job_name} — skipping normalization")
        return

    logger.info(f"[Normalize] Normalizing {len(to_normalize)} new file(s) from {job_name}")
    try:
        _call_normalize(to_normalize)
        logger.info(f"[Normalize] Finished normalization for files from {job_name}")
    except Exception as e:
        logger.exception(f"[Normalize] Normalization failed for {job_name}: {e}")


# --- Scheduling ---
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
    scheduled = set()

    def monthly_wrapper(fn_name: str):
        def wrapper():
            # run only on day 1 of month
            if time.localtime().tm_mday == 1:
                run_pipeline(fn_name)
            else:
                logger.debug(f"[Scheduler] Skipping monthly job {fn_name} (today != 1)")
        return wrapper

    for job in FEED_REGISTRY:
        name = job.__name__
        if name in scheduled:
            continue
        scheduled.add(name)

        if name in {"fetch_urlhaus_csv_online", "fetch_feodo", "fetch_ciarmy"}:
            schedule.every().day.at(SCHEDULE_TIME).do(monthly_wrapper(name))
            logger.info(f" • {name}: monthly (day=1 @ {SCHEDULE_TIME})")
        elif name == "fetch_threatfox":
            # schedule every 48 hours
            schedule.every(48).hours.do(lambda n=name: run_pipeline(n))
            logger.info(f" • {name}: every 48 hours")
        else:
            schedule.every().day.at(SCHEDULE_TIME).do(lambda n=name: run_pipeline(n))
            logger.info(f" • {name}: daily @ {SCHEDULE_TIME}")

    logger.info("[Scheduler] Job scheduling complete.")


def initial_run() -> None:
    """
    Run one fetch+normalize for every feed at startup.
    """
    logger.info("[Startup] Running initial collection + normalization for all feeds…")
    for job in FEED_REGISTRY:
        run_pipeline(job.__name__)


def run_scheduler() -> None:
    """
    Main loop: run pending scheduled jobs and emit heartbeat every HEARTBEAT_INTERVAL.
    """
    logger.info("[Runtime] Scheduler started. Waiting for jobs…")
    last_heartbeat = time.time()

    try:
        while True:
            schedule.run_pending()
            if time.time() - last_heartbeat >= HEARTBEAT_INTERVAL:
                logger.info("[Heartbeat] Scheduler alive — collector/normalizer healthy")
                last_heartbeat = time.time()
            time.sleep(SLEEP_INTERVAL)
    except KeyboardInterrupt:
        logger.info("[Shutdown] Interrupted by user")
    except Exception as e:
        logger.exception(f"[Scheduler] Unexpected runtime error: {e}")


def main() -> None:
    logger.info("[Init] DeltaTI starting")
    ensure_data_dir()   # from collectors.utils.file_utils
    initial_run()
    schedule_jobs()
    run_scheduler()


if __name__ == "__main__":
    main()