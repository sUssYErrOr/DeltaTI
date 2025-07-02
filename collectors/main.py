#!/usr/bin/env python3
"""
main.py

Entry point for DeltaTI Collector + Normalizer pipeline.
Schedules fetch jobs and triggers normalization upon completion.
"""

import sys
import time
import logging
from pathlib import Path
from typing import Callable
import schedule

from collectors.feeds.fetchers import FEED_REGISTRY
from Normalizer.normalizer import normalize_all
from collectors.utils.file_utils import ensure_data_dir

# Constants
SCHEDULE_TIME = "22:00"
SLEEP_INTERVAL = 30
HEARTBEAT_INTERVAL = 7200

try:
    project_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(project_root))
except Exception as e:
    raise RuntimeError("Failed to resolve project root") from e

# --- Configure Logging ---
logger = logging.getLogger("DeltaTI")
logger.setLevel(logging.INFO)
logger.propagate = False

for handler in list(logger.handlers):
    logger.removeHandler(handler)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))
logger.addHandler(stream_handler)

def run_pipeline(job_func_name: str) -> None:
    """
    Executes a feed fetching job followed by normalization.

    Args:
        job_func_name (str): The name of the job function in FEED_REGISTRY.
    """
    job_func: Callable | None = next((j for j in FEED_REGISTRY if j.__name__ == job_func_name), None)

    if not job_func:
        logger.error(f"[Error] Job function '{job_func_name}' not found in registry.")
        return

    logger.info(f"[Fetch] Starting job: {job_func.__name__}")
    try:
        job_func()
        logger.info(f"[Fetch] Completed job: {job_func.__name__}")
    except Exception as fetch_error:
        logger.exception(f"[Fetch] Failed: {job_func.__name__}: {fetch_error}")

    logger.info("[Normalize] Starting normalization...")
    try:
        normalize_all()
        logger.info(f"[Normalize] Normalization completed for job: {job_func.__name__}")
    except Exception as norm_error:
        logger.exception(f"[Normalize] Failed: {norm_error}")


def schedule_jobs() -> None:
    """
    Schedules each job in FEED_REGISTRY to run daily at the specified time.
    """
    logger.info(f"[Scheduler] Scheduling jobs at {SCHEDULE_TIME} daily...")
    for job in FEED_REGISTRY:
        job_name = job.__name__
        schedule.every().day.at(SCHEDULE_TIME).do(lambda jn=job_name: run_pipeline(jn))
        logger.info(f"[Scheduler] Scheduled job '{job_name}' at {SCHEDULE_TIME}")


def initial_run() -> None:
    """
    Executes all jobs once at startup to populate initial data.
    """
    logger.info("[Startup] Running initial data collection and normalization...")
    for job in FEED_REGISTRY:
        run_pipeline(job.__name__)


def run_scheduler() -> None:
    """
    Continuously runs scheduled tasks, logs after jobs, and logs status every 5 minutes.
    """
    logger.info("[Runtime] Scheduler started. Awaiting scheduled jobs...")
    last_heartbeat = time.time()

    try:
        while True:
            ran_job = schedule.run_pending()

            if ran_job:
                logger.info("[Status] A scheduled job has just completed.")

            if time.time() - last_heartbeat >= HEARTBEAT_INTERVAL:
                logger.info("[Heartbeat] Collector is working normally...")
                last_heartbeat = time.time()

            time.sleep(SLEEP_INTERVAL)

    except KeyboardInterrupt:
        logger.info("[Shutdown] Scheduler interrupted by user.")
    except Exception as scheduler_error:
        logger.exception(f"[Scheduler] Unexpected runtime error: {scheduler_error}")


def main() -> None:
    """
    Main entry point for the DeltaTI pipeline.
    """
    logger.info("[Init] DeltaTI is initializing...")
    ensure_data_dir()
    initial_run()
    schedule_jobs()
    run_scheduler()


if __name__ == '__main__':
    main()