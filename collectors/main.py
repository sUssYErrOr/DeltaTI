"""
main.py

Entry point for DeltaTI Collector + Normalizer pipeline.
Schedules fetch jobs, then triggers normalization upon completion.
"""
import sys
import time
import logging
from pathlib import Path
import schedule

# Set up root path for module imports
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Imports from DeltaTI modules
from collectors.feeds.fetchers import FEED_REGISTRY
from Normalizer.normalizer import normalize_all
from collectors.utils.file_utils import ensure_data_dir

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def run_pipeline(job_func):
    """
    Run a fetch job followed by a normalization process.

    Args:
        job_func (Callable): A function that fetches a feed.
    """
    try:
        logger.info(f"Starting fetch job: {job_func.__name__}")
        job_func()
    except Exception as fetch_error:
        logger.exception(f"Fetch failed: {job_func.__name__}: {fetch_error}")

    try:
        logger.info("Starting normalization run...")
        normalize_all()
    except Exception as norm_error:
        logger.exception(f"Normalization run failed: {norm_error}")

def schedule_jobs(interval_hours=2):
    """
    Schedule each feed job with the specified interval.

    Args:
        interval_hours (int): Interval in hours to run the jobs.
    """
    for job in FEED_REGISTRY:
        schedule.every(interval_hours).hours.do(run_pipeline, job)
        logger.info(f"Scheduled job {job.__name__} every {interval_hours} hours.")

def initial_run():
    """
    Run all feed jobs once on startup.
    """
    for job in FEED_REGISTRY:
        run_pipeline(job)

def run_scheduler():
    """
    Run the scheduler to manage periodic feed and normalization tasks.
    """
    logger.info("Collector + Normalizer started; awaiting scheduled runs...")
    while True:
        try:
            schedule.run_pending()
            time.sleep(30)
        except KeyboardInterrupt:
            logger.info("Shutting down scheduler.")
            break
        except Exception as scheduler_error:
            logger.exception(f"Unexpected error in scheduler: {scheduler_error}")

def main():
    """
    Main entry point for running the DeltaTI pipeline.
    """
    ensure_data_dir()
    schedule_jobs()
    initial_run()
    run_scheduler()

if __name__ == '__main__':
    main()