# scoring/scorer.py
import json
import math
import logging
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import hashlib
import re

# Setup logging to match your existing format
logger = logging.getLogger(__name__)

# Get project paths to match your structure
project_root = Path(__file__).resolve().parent.parent
feeds_dir = project_root / 'collectors' / 'data' / 'feeds'
normalized_dir = project_root / 'Normalizer' / 'normalized_data'
scored_dir = project_root / 'scoring' / 'scored_data'
scored_dir.mkdir(parents=True, exist_ok=True)

@dataclass
class IOCScore:
    """Complete scoring information for an IOC"""
    indicator: str
    ioc_type: str
    base_confidence: float
    source_score: float
    freshness_score: float
    correlation_score: float
    false_positive_risk: float
    final_score: float
    sources: List[str]
    first_seen: str
    last_seen: str
    seen_count: int
    tags: List[str]
    threat_actors: List[str]
    campaigns: List[str]
    malware_families: List[str]
    decay_factor: float
    raw_records: List[Dict]
    quality_grade: str  # A, B, C, D based on final_score

class ThreatIntelligenceScorer:
    """Advanced IOC scoring and correlation engine"""
    
    def __init__(self):
        self.config = self.load_scoring_config()
        self.ioc_database: Dict[str, IOCScore] = {}
        self.cache_file = scored_dir / 'ioc_scores_cache.json'
        
        # Source reputation scores based on your feeds
        self.source_reputation = {
            'urlhaus': 95,
            'threatfox': 95, 
            'feodo': 90,
            'malshare': 85,
            'bazaar': 85,
            'bazaar_recent': 85,
            'bazaar_yara': 85,
            'phishtank': 90,
            'phishstats': 75,
            'otx': 80,
            'spamhaus': 90,
            'emerging_threats': 85,
            'ciarmy': 70,
            'dshield': 80,
            'dshield_openioc': 80,
            'dshield_threatfeeds': 80
        }
        
        # IOC type lifespans (days) 
        self.ioc_lifespans = {
            'url': 7,
            'domain': 30, 
            'ipv4-addr': 14,
            'file-sha256': 365,
            'file-sha1': 365,
            'file-md5': 365
        }
        
        # False positive patterns
        self.false_positive_patterns = [
            re.compile(r'\b(google|microsoft|amazon|cloudflare|facebook|twitter|github|stackoverflow)\.com$', re.I),
            re.compile(r'\b(localhost|127\.0\.0\.1|0\.0\.0\.0)$', re.I),
            re.compile(r'\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)', re.I),
            re.compile(r'\.(amazonaws|cloudfront|azure|googleapis|github\.io)', re.I),
            re.compile(r'\b(example\.(com|org|net)|test\.)', re.I)
        ]
        
        # Load existing scores
        self.load_existing_scores()
    
    def load_scoring_config(self) -> Dict:
        """Load scoring configuration with your project structure"""
        return {
            'weights': {
                'source_weight': 0.35,
                'freshness_weight': 0.25,
                'correlation_weight': 0.25,
                'fp_risk_weight': 0.15
            },
            'thresholds': {
                'grade_a': 85,  # High confidence
                'grade_b': 70,  # Medium-high confidence  
                'grade_c': 50,  # Medium confidence
                'grade_d': 30   # Low confidence
            },
            'correlation': {
                'min_sources_for_boost': 2,
                'max_correlation_bonus': 25
            }
        }
    
    def calculate_source_score(self, sources: List[str]) -> float:
        """Calculate score based on source reputation"""
        if not sources:
            return 50.0
        
        reputation_scores = []
        for source in sources:
            source_clean = source.lower()
            
            # Direct lookup or partial matching
            score = self.source_reputation.get(source_clean, 50)
            if score == 50:  # Try partial matching
                for known_source, rep_score in self.source_reputation.items():
                    if known_source in source_clean or source_clean in known_source:
                        score = rep_score
                        break
            
            reputation_scores.append(score)
        
        # Weighted average favoring higher reputation sources
        max_score = max(reputation_scores)
        avg_score = sum(reputation_scores) / len(reputation_scores)
        return (max_score * 0.7) + (avg_score * 0.3)
    
    def calculate_freshness_score(self, first_seen: str, last_seen: str, ioc_type: str) -> Tuple[float, float]:
        """Calculate freshness score and decay factor"""
        try:
            # Parse the last_seen timestamp from your normalizer format
            if last_seen:
                last_seen_dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
            else:
                last_seen_dt = datetime.now(timezone.utc)
            
            now = datetime.now(timezone.utc)
            age_days = (now - last_seen_dt).total_seconds() / (24 * 3600)
            
            # Get expected lifespan for this IOC type
            expected_lifespan = self.ioc_lifespans.get(ioc_type, 30)
            
            # Exponential decay
            decay_factor = math.exp(-0.1 * (age_days / expected_lifespan))
            freshness_score = max(0, min(100, decay_factor * 100))
            
            return freshness_score, decay_factor
            
        except Exception as e:
            logger.warning(f"Freshness calculation failed: {e}")
            return 50.0, 0.5
    
    def calculate_correlation_score(self, indicator: str, sources: List[str]) -> float:
        """Calculate cross-source correlation score"""
        unique_sources = len(set(sources))
        
        if unique_sources < 2:
            return 0.0
        
        # Logarithmic bonus for multiple sources
        max_bonus = self.config['correlation']['max_correlation_bonus']
        bonus = min(max_bonus, max_bonus * math.log(unique_sources) / math.log(5))
        
        return bonus
    
    def calculate_false_positive_risk(self, indicator: str, ioc_type: str) -> float:
        """Calculate false positive risk (0-100, lower is better)"""
        risk_score = 0.0
        
        # Check against FP patterns
        for pattern in self.false_positive_patterns:
            if pattern.search(indicator):
                risk_score += 40
                break
        
        # Type-specific risk assessment
        if ioc_type == 'url':
            if len(indicator) < 15:
                risk_score += 10
            if any(legit in indicator.lower() for legit in ['microsoft', 'google', 'amazon', 'github']):
                risk_score += 25
        
        elif ioc_type == 'domain':
            if len(indicator) < 4:
                risk_score += 20
            # Check for suspicious patterns
            if len(indicator) > 25 and indicator.count('.') < 2:
                risk_score += 5  # Might be DGA
        
        return min(100, risk_score)
    
    def calculate_final_score(self, source_score: float, freshness_score: float, 
                            correlation_score: float, fp_risk: float) -> float:
        """Calculate weighted final score"""
        weights = self.config['weights']
        
        fp_contribution = 100 - fp_risk  # Invert FP risk
        
        final_score = (
            (source_score * weights['source_weight']) +
            (freshness_score * weights['freshness_weight']) +
            (correlation_score * weights['correlation_weight']) +
            (fp_contribution * weights['fp_risk_weight'])
        )
        
        return min(100, max(0, final_score))
    
    def assign_quality_grade(self, final_score: float) -> str:
        """Assign quality grade based on final score"""
        thresholds = self.config['thresholds']
        
        if final_score >= thresholds['grade_a']:
            return 'A'
        elif final_score >= thresholds['grade_b']:
            return 'B'
        elif final_score >= thresholds['grade_c']:
            return 'C'
        else:
            return 'D'
    
    def extract_threat_context(self, records: List[Dict]) -> Tuple[List[str], List[str], List[str]]:
        """Extract threat intelligence context from your normalized records"""
        threat_actors = set()
        campaigns = set()
        malware_families = set()
        
        for record in records:
            # Extract from tags (your normalizer adds these)
            tags = record.get('tags', [])
            for tag in tags:
                if isinstance(tag, str):
                    tag_lower = tag.lower()
                    
                    # Threat actor patterns
                    if any(pattern in tag_lower for pattern in ['apt', 'lazarus', 'carbanak', 'fin', 'actor']):
                        threat_actors.add(tag)
                    # Campaign patterns  
                    elif any(pattern in tag_lower for pattern in ['campaign', 'operation', 'attack']):
                        campaigns.add(tag)
                    # Malware patterns
                    elif any(pattern in tag_lower for pattern in ['trojan', 'banker', 'stealer', 'loader', 'rat', 'malware']):
                        malware_families.add(tag)
            
            # Extract from raw data (your normalizer preserves original data)
            raw = record.get('raw', {})
            if isinstance(raw, dict):
                # ThreatFox fields
                for field in ['malware', 'malware_alias', 'threat']:
                    if field in raw and raw[field]:
                        malware_families.add(raw[field])
                
                # OTX fields
                if 'malware_families' in raw:
                    if isinstance(raw['malware_families'], list):
                        malware_families.update(raw['malware_families'])
        
        return list(threat_actors), list(campaigns), list(malware_families)
    
    def process_normalized_files(self, file_paths: List[Path] = None) -> Dict[str, IOCScore]:
        """Process normalized files from your normalizer"""
        if file_paths is None:
            file_paths = list(normalized_dir.glob("normalized_*.json"))
        
        all_records = []
        
        # Load normalized records (your format)
        for file_path in file_paths:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    records = json.load(f)
                    if isinstance(records, list):
                        all_records.extend(records)
                        logger.info(f"[Scorer] Loaded {len(records)} records from {file_path.name}")
                    else:
                        logger.warning(f"[Scorer] Expected list in {file_path.name}, got {type(records)}")
            except Exception as e:
                logger.error(f"[Scorer] Failed to load {file_path.name}: {e}")
        
        if not all_records:
            logger.warning("[Scorer] No records found to score")
            return {}
        
        # Group and score records
        return self.score_records(all_records)
    
    def score_records(self, records: List[Dict]) -> Dict[str, IOCScore]:
        """Score a list of normalized records"""
        # Group by indicator + type
        ioc_groups = defaultdict(lambda: {
            'sources': [],
            'records': [],
            'first_seen': None,
            'last_seen': None,
            'tags': set(),
            'ioc_type': None
        })
        
        # Validate and group records
        valid_count = 0
        for record in records:
            # Validate required fields (your normalizer format)
            if not all(field in record for field in ['indicator', 'type', 'source']):
                continue
                
            indicator = record['indicator'].strip()
            if not indicator:
                continue
                
            ioc_type = record['type']
            source = record['source']
            
            key = f"{indicator}|{ioc_type}"
            group = ioc_groups[key]
            
            group['sources'].append(source)
            group['records'].append(record)
            group['ioc_type'] = ioc_type
            
            # Handle tags safely
            tags = record.get('tags', [])
            if isinstance(tags, list):
                group['tags'].update(tags)
            
            # Track timing
            first_seen = record.get('first_seen')
            last_seen = record.get('last_seen')
            
            if first_seen and (not group['first_seen'] or first_seen < group['first_seen']):
                group['first_seen'] = first_seen
            if last_seen and (not group['last_seen'] or last_seen > group['last_seen']):
                group['last_seen'] = last_seen
            
            valid_count += 1
        
            logger.info(f"[Scorer] Processing {valid_count} valid records grouped into {len(ioc_groups)} unique IOCs")
        
        # Score each IOC group
        scored_iocs = {}
        
        for key, group in ioc_groups.items():
            try:
                indicator, ioc_type = key.split('|', 1)
                
                # Ensure we have valid dates
                if not group['first_seen']:
                    group['first_seen'] = datetime.now(timezone.utc).isoformat()
                if not group['last_seen']:
                    group['last_seen'] = group['first_seen']
                
                # Calculate component scores
                source_score = self.calculate_source_score(group['sources'])
                freshness_score, decay_factor = self.calculate_freshness_score(
                    group['first_seen'], group['last_seen'], ioc_type
                )
                correlation_score = self.calculate_correlation_score(indicator, group['sources'])
                fp_risk = self.calculate_false_positive_risk(indicator, ioc_type)
                
                # Calculate final score
                final_score = self.calculate_final_score(
                    source_score, freshness_score, correlation_score, fp_risk
                )
                
                # Extract threat context
                threat_actors, campaigns, malware_families = self.extract_threat_context(group['records'])
                
                # Calculate base confidence
                confidences = [r.get('confidence', 80) for r in group['records'] 
                             if isinstance(r.get('confidence'), (int, float))]
                base_confidence = sum(confidences) / len(confidences) if confidences else 80
                
                # Assign quality grade
                quality_grade = self.assign_quality_grade(final_score)
                
                # Create IOCScore object
                ioc_score = IOCScore(
                    indicator=indicator,
                    ioc_type=ioc_type,
                    base_confidence=base_confidence,
                    source_score=source_score,
                    freshness_score=freshness_score,
                    correlation_score=correlation_score,
                    false_positive_risk=fp_risk,
                    final_score=final_score,
                    sources=list(set(group['sources'])),
                    first_seen=group['first_seen'],
                    last_seen=group['last_seen'],
                    seen_count=len(group['records']),
                    tags=list(group['tags']),
                    threat_actors=threat_actors,
                    campaigns=campaigns,
                    malware_families=malware_families,
                    decay_factor=decay_factor,
                    raw_records=group['records'],
                    quality_grade=quality_grade
                )
                
                scored_iocs[key] = ioc_score
                self.ioc_database[key] = ioc_score
                
            except Exception as e:
                logger.error(f"[Scorer] Failed to score IOC {key}: {e}")
                continue
        
        logger.info(f"[Scorer] Successfully scored {len(scored_iocs)} unique IOCs")
        return scored_iocs
    
    def update_scores_with_new_data(self, new_records: List[Dict]) -> Dict[str, IOCScore]:
        """Update existing scores with new data"""
        logger.info(f"[Scorer] Updating scores with {len(new_records)} new records")
        
        # Combine with existing data
        all_records = new_records.copy()
        
        # Add existing records back for re-scoring
        for ioc_score in self.ioc_database.values():
            all_records.extend(ioc_score.raw_records)
        
        # Re-score everything
        return self.score_records(all_records)
    
    def get_high_value_iocs(self, min_score: float = None, grade: str = None) -> List[IOCScore]:
        """Get high-value IOCs based on score or grade"""
        if grade:
            return [ioc for ioc in self.ioc_database.values() if ioc.quality_grade == grade]
        
        if min_score is None:
            min_score = self.config['thresholds']['grade_b']
        
        return [ioc for ioc in self.ioc_database.values() if ioc.final_score >= min_score]
    
    def get_trending_threats(self, days: int = 7) -> Dict:
        """Get trending threats from recent IOCs"""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        recent_iocs = []
        
        for ioc in self.ioc_database.values():
            try:
                last_seen = datetime.fromisoformat(ioc.last_seen.replace('Z', '+00:00'))
                if last_seen >= cutoff_date:
                    recent_iocs.append(ioc)
            except:
                continue
        
        # Count threat elements
        malware_counter = Counter()
        actor_counter = Counter()
        source_counter = Counter()
        type_counter = Counter()
        
        for ioc in recent_iocs:
            malware_counter.update(ioc.malware_families)
            actor_counter.update(ioc.threat_actors)
            source_counter.update(ioc.sources)
            type_counter[ioc.ioc_type] += 1
        
        return {
            'period_days': days,
            'total_recent_iocs': len(recent_iocs),
            'trending_malware': dict(malware_counter.most_common(10)),
            'active_threat_actors': dict(actor_counter.most_common(10)),
            'most_active_sources': dict(source_counter.most_common(10)),
            'ioc_type_distribution': dict(type_counter.most_common())
        }
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics"""
        if not self.ioc_database:
            return {'total_iocs': 0}
        
        scores = [ioc.final_score for ioc in self.ioc_database.values()]
        grades = [ioc.quality_grade for ioc in self.ioc_database.values()]
        
        grade_dist = Counter(grades)
        type_dist = Counter(ioc.ioc_type for ioc in self.ioc_database.values())
        source_dist = Counter()
        
        for ioc in self.ioc_database.values():
            source_dist.update(ioc.sources)
        
        return {
            'total_iocs': len(self.ioc_database),
            'score_statistics': {
                'mean': sum(scores) / len(scores),
                'min': min(scores),
                'max': max(scores)
            },
            'grade_distribution': dict(grade_dist),
            'type_distribution': dict(type_dist),
            'source_distribution': dict(source_dist.most_common(15)),
            'quality_breakdown': {
                'high_quality_pct': (grade_dist['A'] / len(grades)) * 100,
                'medium_quality_pct': ((grade_dist['B'] + grade_dist['C']) / len(grades)) * 100,
                'low_quality_pct': (grade_dist['D'] / len(grades)) * 100
            }
        }
    
    def save_scores(self) -> None:
        """Save scores to cache file"""
        try:
            cache_data = {
                'metadata': {
                    'total_iocs': len(self.ioc_database),
                    'last_updated': datetime.now(timezone.utc).isoformat(),
                    'version': '1.0'
                },
                'scores': {k: asdict(v) for k, v in self.ioc_database.items()}
            }
            
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, default=str)
            
            logger.info(f"[Scorer] Saved {len(self.ioc_database)} scores to {self.cache_file}")
        except Exception as e:
            logger.error(f"[Scorer] Failed to save scores: {e}")
    
    def load_existing_scores(self) -> None:
        """Load existing scores from cache"""
        if not self.cache_file.exists():
            logger.info("[Scorer] No existing scores cache found")
            return
        
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            scores_data = data.get('scores', {})
            for key, score_dict in scores_data.items():
                # Convert back to IOCScore object
                ioc_score = IOCScore(**score_dict)
                self.ioc_database[key] = ioc_score
            
            logger.info(f"[Scorer] Loaded {len(self.ioc_database)} existing scores")
        except Exception as e:
            logger.error(f"[Scorer] Failed to load existing scores: {e}")
    
    def export_results(self, format: str = 'json', min_score: float = None) -> None:
        """Export scored results in various formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Get IOCs to export
        if min_score:
            iocs_to_export = [ioc for ioc in self.ioc_database.values() if ioc.final_score >= min_score]
            filename_suffix = f"_min{int(min_score)}"
        else:
            iocs_to_export = list(self.ioc_database.values())
            filename_suffix = ""
        
        if format.lower() == 'json':
            output_file = scored_dir / f"scored_iocs{filename_suffix}_{timestamp}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump([asdict(ioc) for ioc in iocs_to_export], f, indent=2, default=str)
        
        elif format.lower() == 'csv':
            import csv
            output_file = scored_dir / f"scored_iocs{filename_suffix}_{timestamp}.csv"
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = [
                    'indicator', 'ioc_type', 'final_score', 'quality_grade', 
                    'sources', 'malware_families', 'first_seen', 'last_seen', 'seen_count'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for ioc in iocs_to_export:
                    writer.writerow({
                        'indicator': ioc.indicator,
                        'ioc_type': ioc.ioc_type,
                        'final_score': round(ioc.final_score, 2),
                        'quality_grade': ioc.quality_grade,
                        'sources': ','.join(ioc.sources),
                        'malware_families': ','.join(ioc.malware_families),
                        'first_seen': ioc.first_seen,
                        'last_seen': ioc.last_seen,
                        'seen_count': ioc.seen_count
                    })
        
        logger.info(f"[Scorer] Exported {len(iocs_to_export)} IOCs to {output_file}")

# Integration with your main pipeline
class ScoringIntegrator:
    """Integrates scoring with your existing pipeline"""
    
    def __init__(self):
        self.scorer = ThreatIntelligenceScorer()
    
    def process_new_normalized_files(self, file_paths: List[Path] = None) -> None:
        """Process newly normalized files and update scores"""
        logger.info("[Scoring] Starting IOC scoring process...")
        
        # Process normalized files
        scored_iocs = self.scorer.process_normalized_files(file_paths)
        
        if scored_iocs:
            # Save updated scores
            self.scorer.save_scores()
            
            # Generate exports
            self.generate_exports()
            
            # Generate reports
            self.generate_reports()
        else:
            logger.warning("[Scoring] No IOCs were scored")
    
    def generate_exports(self) -> None:
        """Generate various export formats"""
        # Export all scored IOCs
        self.scorer.export_results('json')
        
        # Export high-quality IOCs only
        self.scorer.export_results('csv', min_score=70)
        
        # Export A-grade IOCs
        a_grade_iocs = self.scorer.get_high_value_iocs(grade='A')
        if a_grade_iocs:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = scored_dir / f"grade_a_iocs_{timestamp}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump([asdict(ioc) for ioc in a_grade_iocs], f, indent=2, default=str)
            logger.info(f"[Scoring] Exported {len(a_grade_iocs)} Grade-A IOCs")
    
    def generate_reports(self) -> None:
        """Generate analysis reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Statistics report
        stats = self.scorer.get_statistics()
        with open(scored_dir / f"scoring_statistics_{timestamp}.json", 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
        
        # Trending threats report
        trends = self.scorer.get_trending_threats(7)  # Last 7 days
        with open(scored_dir / f"trending_threats_{timestamp}.json", 'w', encoding='utf-8') as f:
            json.dump(trends, f, indent=2)
        
        # Summary report for logging
        logger.info("[Scoring] === Scoring Summary ===")
        logger.info(f"  Total IOCs: {stats['total_iocs']:,}")
        logger.info(f"  Grade A (High): {stats['grade_distribution'].get('A', 0):,}")
        logger.info(f"  Grade B (Med-High): {stats['grade_distribution'].get('B', 0):,}")
        logger.info(f"  Grade C (Medium): {stats['grade_distribution'].get('C', 0):,}")
        logger.info(f"  Grade D (Low): {stats['grade_distribution'].get('D', 0):,}")
        logger.info(f"  Average Score: {stats['score_statistics']['mean']:.1f}")
        
        if trends['trending_malware']:
            top_malware = list(trends['trending_malware'].items())[:3]
            logger.info(f"  Top Malware: {', '.join([f'{name}({count})' for name, count in top_malware])}")

# Integration function for your main.py
async def score_normalized_data(normalized_files: List[Path] = None) -> None:
    """
    Async function to score normalized data
    Call this from your main pipeline after normalization
    """
    try:
        integrator = ScoringIntegrator()
        
        # Run scoring in thread pool to not block async loop
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            await loop.run_in_executor(
                executor, 
                integrator.process_new_normalized_files, 
                normalized_files
            )
        
        logger.info("[Scoring] Async scoring completed")
        
    except Exception as e:
        logger.exception(f"[Scoring] Async scoring failed: {e}")

# CLI interface
def main():
    """Main scoring function for standalone use"""
    import argparse
    
    parser = argparse.ArgumentParser(description="IOC Scoring Engine")
    parser.add_argument("--files", nargs="+", type=Path, help="Specific normalized files to score")
    parser.add_argument("--export-format", choices=['json', 'csv'], default='json')
    parser.add_argument("--min-score", type=float, help="Minimum score for export")
    parser.add_argument("--stats-only", action="store_true", help="Only show statistics")
    
    args = parser.parse_args()
    
    integrator = ScoringIntegrator()
    
    if args.stats_only:
        stats = integrator.scorer.get_statistics()
        print("\n=== IOC Scoring Statistics ===")
        print(f"Total IOCs: {stats.get('total_iocs', 0):,}")
        if stats.get('grade_distribution'):
            for grade, count in stats['grade_distribution'].items():
                print(f"  Grade {grade}: {count:,}")
        print(f"Average Score: {stats.get('score_statistics', {}).get('mean', 0):.2f}")
    else:
        integrator.process_new_normalized_files(args.files)

if __name__ == '__main__':
    main()