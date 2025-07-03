import sys
import time
import logging
from pathlib import Path
from typing import Callable, List
import schedule

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from collectors.feeds.fetchers import FEED_REGISTRY
from Normalizer.normalizer import normalize_all
from collectors.utils.file_utils import ensure_data_dir

logger = logging.getLogger("DeltaTI")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))
    logger.addHandler(sh)

SCHEDULE_TIME    = "22:00"   # daily trigger time
SLEEP_INTERVAL   = 30        # seconds between loop iterations
HEARTBEAT_INTERVAL = 7200    # seconds (2 hours)

# --- Data Directories ---
FEEDS_DIR        = project_root / "collectors" / "data" / "feeds"
NORMALIZED_DIR   = project_root / "Normalizer" / "normalized_data"

def list_raw_files() -> set:
    """
    List only raw feed files (skip any normalized outputs).
    """
    return {
        p.name for p in FEEDS_DIR.iterdir()
        if p.is_file() and not p.name.startswith("normalized_")
    }

def run_pipeline(job_name: str) -> None:
    """
    Run one fetcher, then normalize only new files that have no existing
    normalized_* output.
    """
    job = next((j for j in FEED_REGISTRY if j.__name__ == job_name), None)
    if not job:
        logger.error(f"[Error] No such job: {job_name}")
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
    candidates = after - before
    # skip any that already have a normalized file
    new_files = []
    for fname in candidates:
        stem = Path(fname).stem
        normalized_name = f"normalized_{stem}.json"
        if (NORMALIZED_DIR / normalized_name).exists():
            logger.info(f"[Normalize] Skipping {fname}: already normalized")
        else:
            new_files.append(fname)

    if not new_files:
        logger.info(f"[Normalize] No unnormalized new files for {job_name}, skipping.")
        return

    paths = [FEEDS_DIR / fn for fn in new_files]
    logger.info(f"[Normalize] Normalizing {len(paths)} file(s) from {job_name}")
    try:
        normalize_all(paths)
        logger.info(f"[Normalize] Done for {job_name}")
    except Exception as e:
        logger.exception(f"[Normalize] Failed for {job_name}: {e}")

def schedule_jobs() -> None:
    """
    Schedule each fetcher at its required interval, without duplicates.
    """
    logger.info("[Scheduler] Setting up job intervals…")
    scheduled = set()

    def every_month(fn_name: str):
        def wrapper():
            if time.localtime().tm_mday == 1:
                run_pipeline(fn_name)
        return wrapper

    def every_48h(fn_name: str):
        return lambda: run_pipeline(fn_name)

    def every_24h(fn_name: str):
        return lambda: run_pipeline(fn_name)

    for job in FEED_REGISTRY:
        name = job.__name__
        if name in scheduled:
            continue
        scheduled.add(name)

        if name in {"fetch_urlhaus_csv_online", "fetch_feodo", "fetch_ciarmy"}:
            # Monthly on day=1 @ SCHEDULE_TIME
            schedule.every().day.at(SCHEDULE_TIME).do(every_month(name))
            logger.info(f" • {name}: monthly (day=1 @ {SCHEDULE_TIME})")
        elif name == "fetch_threatfox":
            # Every 48 hours
            schedule.every(48).hours.do(every_48h(name))
            logger.info(f" • {name}: every 48h")
        else:
            # All others daily @ SCHEDULE_TIME
            schedule.every().day.at(SCHEDULE_TIME).do(every_24h(name))
            logger.info(f" • {name}: daily @ {SCHEDULE_TIME}")

def initial_run() -> None:
    logger.info("[Startup] Running initial collection + normalization for all feeds…")
    for job in FEED_REGISTRY:
        run_pipeline(job.__name__)

def run_scheduler() -> None:
    logger.info("[Runtime] Scheduler started. Waiting for jobs…")
    last_beat = time.time()

    try:
        while True:
            schedule.run_pending()
            now = time.time()
            if now - last_beat >= HEARTBEAT_INTERVAL:
                logger.info("[Heartbeat] Scheduler is alive")
                last_beat = now
            time.sleep(SLEEP_INTERVAL)
    except KeyboardInterrupt:
        logger.info("[Shutdown] Interrupted by user")
    except Exception as e:
        logger.exception(f"[Scheduler] Unexpected error: {e}")

def main() -> None:
    logger.info("[Init] DeltaTI starting")
    ensure_data_dir()
    initial_run()
    schedule_jobs()
    run_scheduler()

if __name__ == "__main__":
    main()