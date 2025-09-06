#!/usr/bin/env python3
"""
main.py - DeltaTI scheduler/runner with integrated scoring

Key improvements:
- Integrated scoring pipeline after normalization
- Tracks normalized files for scoring
- Creates scored data directory
- Enhanced logging for full pipeline visibility
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
from scoring.scorer import ScoringIntegrator

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
SCORED_DIR = project_root / "scoring" / "scored_data"

# ensure directories exist
FEEDS_DIR.mkdir(parents=True, exist_ok=True)
NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
SCORED_DIR.mkdir(parents=True, exist_ok=True)

# --- Global scoring integrator instance ---
scoring_integrator = None

def get_scoring_integrator():
    """Get or create scoring integrator instance"""
    global scoring_integrator
    if scoring_integrator is None:
        try:
            scoring_integrator = ScoringIntegrator()
            logger.info("[Scoring] Initialized scoring integrator")
        except Exception as e:
            logger.error(f"[Scoring] Failed to initialize scoring integrator: {e}")
            scoring_integrator = None
    return scoring_integrator


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


def _call_normalize(paths: List[Path]) -> List[Path]:
    """
    Call normalize_all either with a list of Path objects (if supported)
    or with no args (fallback).
    Returns list of normalized file paths that were created.
    """
    # Track which normalized files exist before normalization
    before_files = set(NORMALIZED_DIR.glob("normalized_*.json"))
    
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
    
    # Track which normalized files were created
    after_files = set(NORMALIZED_DIR.glob("normalized_*.json"))
    new_normalized = list(after_files - before_files)
    
    return new_normalized


def score_normalized_files(normalized_paths: List[Path]) -> bool:
    """
    Score the normalized files. Returns True if successful.
    """
    if not normalized_paths:
        logger.info("[Score] No files to score")
        return True
        
    integrator = get_scoring_integrator()
    if not integrator:
        logger.warning("[Score] Scoring integrator not available, skipping scoring")
        return False
    
    try:
        logger.info(f"[Score] Scoring {len(normalized_paths)} normalized file(s)")
        integrator.process_new_normalized_files(normalized_paths)
        logger.info("[Score] Scoring completed successfully")
        return True
    except Exception as e:
        logger.exception(f"[Score] Scoring failed: {e}")
        return False


# --- Core pipeline ---
def run_pipeline(job_name: str) -> None:
    """
    Run one fetcher job, then normalize newly created files, then score them.
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

    # Filter out any created files that already have normalized output
    to_normalize = []
    existing_normalized = []  # Track already normalized files for potential re-scoring
    
    for fname in created:
        stem = Path(fname).stem
        normalized_path = NORMALIZED_DIR / f"normalized_{stem}.json"
        
        if already_normalized_for(stem):
            logger.info(f"[Normalize] Skipping {fname} — already normalized")
            # Still track for scoring in case it needs re-scoring
            if normalized_path.exists():
                existing_normalized.append(normalized_path)
        else:
            to_normalize.append(FEEDS_DIR / fname)

    # Normalize new files
    new_normalized_files = []
    if to_normalize:
        logger.info(f"[Normalize] Normalizing {len(to_normalize)} new file(s) from {job_name}")
        try:
            new_normalized_files = _call_normalize(to_normalize)
            logger.info(f"[Normalize] Finished normalization for {len(new_normalized_files)} files from {job_name}")
        except Exception as e:
            logger.exception(f"[Normalize] Normalization failed for {job_name}: {e}")
            return
    else:
        logger.info(f"[Normalize] No new un-normalized files from {job_name}")

    # Score all relevant normalized files (new + existing from this job)
    all_normalized_to_score = new_normalized_files + existing_normalized
    
    if all_normalized_to_score:
        score_normalized_files(all_normalized_to_score)
    else:
        logger.info(f"[Score] No normalized files to score from {job_name}")


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
    Run one fetch+normalize+score for every feed at startup.
    """
    logger.info("[Startup] Running initial collection + normalization + scoring for all feeds…")
    
    # Initialize scoring integrator early
    get_scoring_integrator()
    
    for job in FEED_REGISTRY:
        run_pipeline(job.__name__)
    
    # After all feeds are processed, generate comprehensive reports
    logger.info("[Startup] Generating initial comprehensive reports…")
    integrator = get_scoring_integrator()
    if integrator:
        try:
            # Re-score all normalized files to ensure consistency
            all_normalized = list(NORMALIZED_DIR.glob("normalized_*.json"))
            if all_normalized:
                logger.info(f"[Startup] Running comprehensive scoring on {len(all_normalized)} normalized files")
                integrator.process_new_normalized_files(all_normalized)
        except Exception as e:
            logger.error(f"[Startup] Comprehensive scoring failed: {e}")


def generate_daily_report() -> None:
    """Generate daily summary report"""
    integrator = get_scoring_integrator()
    if not integrator:
        return
        
    try:
        logger.info("[Report] Generating daily summary report")
        stats = integrator.scorer.get_statistics()
        trends = integrator.scorer.get_trending_threats(1)  # Last 24 hours
        
        logger.info("[Report] === Daily Summary ===")
        logger.info(f"  Total IOCs: {stats['total_iocs']:,}")
        logger.info(f"  Grade Distribution: A={stats['grade_distribution'].get('A', 0)}, "
                   f"B={stats['grade_distribution'].get('B', 0)}, "
                   f"C={stats['grade_distribution'].get('C', 0)}, "
                   f"D={stats['grade_distribution'].get('D', 0)}")
        logger.info(f"  New IOCs (24h): {trends['total_recent_iocs']:,}")
        
        if trends['trending_malware']:
            top_malware = list(trends['trending_malware'].items())[:3]
            logger.info(f"  Top Malware: {', '.join([f'{m[0]} ({m[1]})' for m in top_malware])}")
        
        if trends.get('trending_up_iocs'):
            logger.info(f"  IOCs Trending Up: {len(trends['trending_up_iocs'])}")
            
        # Save detailed report
        integrator.generate_reports()
        
    except Exception as e:
        logger.error(f"[Report] Daily report generation failed: {e}")


def run_scheduler() -> None:
    """
    Main loop: run pending scheduled jobs and emit heartbeat every HEARTBEAT_INTERVAL.
    """
    logger.info("[Runtime] Scheduler started. Waiting for jobs…")
    last_heartbeat = time.time()
    last_daily_report = time.time()
    
    # Schedule daily report generation
    schedule.every().day.at("23:00").do(generate_daily_report)
    logger.info("[Scheduler] Daily report scheduled for 23:00")

    try:
        while True:
            schedule.run_pending()
            
            # Heartbeat with basic stats
            if time.time() - last_heartbeat >= HEARTBEAT_INTERVAL:
                logger.info("[Heartbeat] Scheduler alive — collector/normalizer/scorer healthy")
                
                # Include basic stats in heartbeat
                integrator = get_scoring_integrator()
                if integrator:
                    try:
                        stats = integrator.scorer.get_statistics()
                        logger.info(f"[Heartbeat] Current stats: {stats['total_iocs']:,} IOCs, "
                                   f"Avg Score: {stats['score_statistics']['mean']:.1f}")
                    except:
                        pass
                
                last_heartbeat = time.time()
            
            time.sleep(SLEEP_INTERVAL)
            
    except KeyboardInterrupt:
        logger.info("[Shutdown] Interrupted by user")
        # Save final state before shutdown
        save_final_state()
    except Exception as e:
        logger.exception(f"[Scheduler] Unexpected runtime error: {e}")
        save_final_state()


def save_final_state() -> None:
    """Save scorer state and generate final reports before shutdown"""
    logger.info("[Shutdown] Saving final state...")
    integrator = get_scoring_integrator()
    
    if integrator and integrator.scorer:
        try:
            # Save current scores
            integrator.scorer.save_scores()
            
            # Generate final reports
            integrator.generate_reports()
            
            # Export high-value IOCs
            integrator.scorer.export_results('json', min_score=80)
            
            logger.info("[Shutdown] Final state saved successfully")
        except Exception as e:
            logger.error(f"[Shutdown] Failed to save final state: {e}")


def health_check() -> dict:
    """
    Perform health check on all components.
    Useful for monitoring or API endpoints.
    """
    health_status = {
        'status': 'healthy',
        'components': {
            'collectors': {'status': 'unknown'},
            'normalizer': {'status': 'unknown'},
            'scorer': {'status': 'unknown'}
        },
        'directories': {
            'feeds': FEEDS_DIR.exists(),
            'normalized': NORMALIZED_DIR.exists(),
            'scored': SCORED_DIR.exists()
        },
        'metrics': {}
    }
    
    # Check collectors
    try:
        feed_count = len(list(FEEDS_DIR.glob("*")))
        health_status['components']['collectors'] = {
            'status': 'healthy',
            'feed_files': feed_count
        }
    except Exception as e:
        health_status['components']['collectors'] = {
            'status': 'unhealthy',
            'error': str(e)
        }
    
    # Check normalizer
    try:
        normalized_count = len(list(NORMALIZED_DIR.glob("normalized_*.json")))
        health_status['components']['normalizer'] = {
            'status': 'healthy',
            'normalized_files': normalized_count
        }
    except Exception as e:
        health_status['components']['normalizer'] = {
            'status': 'unhealthy',
            'error': str(e)
        }
    
    # Check scorer
    integrator = get_scoring_integrator()
    if integrator and integrator.scorer:
        try:
            stats = integrator.scorer.get_statistics()
            health_status['components']['scorer'] = {
                'status': 'healthy',
                'total_iocs': stats['total_iocs'],
                'avg_score': round(stats['score_statistics']['mean'], 2) if stats['total_iocs'] > 0 else 0
            }
            health_status['metrics'] = {
                'grade_distribution': stats.get('grade_distribution', {}),
                'type_distribution': stats.get('type_distribution', {})
            }
        except Exception as e:
            health_status['components']['scorer'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
    else:
        health_status['components']['scorer'] = {
            'status': 'unavailable',
            'error': 'Scorer not initialized'
        }
    
    # Overall status
    unhealthy_components = [
        comp for comp, details in health_status['components'].items()
        if details.get('status') != 'healthy'
    ]
    
    if unhealthy_components:
        health_status['status'] = 'degraded' if len(unhealthy_components) < 3 else 'unhealthy'
        health_status['unhealthy_components'] = unhealthy_components
    
    return health_status


def main() -> None:
    """Main entry point for DeltaTI"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DeltaTI Threat Intelligence Platform")
    parser.add_argument("--health-check", action="store_true", help="Run health check and exit")
    parser.add_argument("--run-once", action="store_true", help="Run all feeds once and exit")
    parser.add_argument("--report-only", action="store_true", help="Generate reports from existing data and exit")
    parser.add_argument("--feed", type=str, help="Run specific feed only")
    
    args = parser.parse_args()
    
    logger.info("[Init] DeltaTI starting")
    ensure_data_dir()   # from collectors.utils.file_utils
    
    if args.health_check:
        health = health_check()
        print(f"Health Status: {health['status']}")
        for component, details in health['components'].items():
            print(f"  {component}: {details}")
        sys.exit(0 if health['status'] == 'healthy' else 1)
    
    elif args.report_only:
        integrator = get_scoring_integrator()
        if integrator:
            logger.info("[Report] Generating reports from existing data...")
            all_normalized = list(NORMALIZED_DIR.glob("normalized_*.json"))
            if all_normalized:
                integrator.process_new_normalized_files(all_normalized)
            else:
                logger.warning("[Report] No normalized data found")
        sys.exit(0)
    
    elif args.feed:
        # Run specific feed
        job = next((j for j in FEED_REGISTRY if j.__name__ == args.feed), None)
        if job:
            logger.info(f"[Init] Running single feed: {args.feed}")
            run_pipeline(args.feed)
        else:
            logger.error(f"[Init] Feed not found: {args.feed}")
            logger.info(f"[Init] Available feeds: {', '.join([j.__name__ for j in FEED_REGISTRY])}")
            sys.exit(1)
        sys.exit(0)
    
    elif args.run_once:
        logger.info("[Init] Running all feeds once")
        initial_run()
        generate_daily_report()
        sys.exit(0)
    
    else:
        # Normal scheduler mode
        initial_run()
        schedule_jobs()
        run_scheduler()


if __name__ == "__main__":
    main()