"""Reproducible benchmark evaluation tool for the URL Threat Intelligence Engine."""

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cyberduel_threat_intel.dataset import DatasetIngestionEngine
from cyberduel_threat_intel.heuristics import URLHeuristicAnalyzer
from cyberduel_threat_intel.normalizer import URLNormalizer
from cyberduel_threat_intel.scoring import RiskScoringEngine, ScoringPolicyConfig

from apps.api.app.repositories.threat_intel_repository import ThreatIntelRepository


def evaluate_dataset(dataset_path: str) -> dict[str, float]:
    """Run benchmark evaluation and output exact confusion matrix and detection metrics."""
    print("=== CyberDuel AI Threat Engine Benchmark Evaluation ===")
    print(f"Dataset path: {dataset_path}\n")

    report = DatasetIngestionEngine.ingest_file(dataset_path)
    print("Dataset summary:")
    print(f"  Rows read:     {report.rows_read}")
    print(f"  Rows accepted: {report.rows_accepted}")
    print(f"  Rows rejected: {report.rows_rejected}")
    print(f"  Distribution:  {report.label_distribution}\n")

    repo = ThreatIntelRepository()
    analyzer = URLHeuristicAnalyzer()
    scoring_engine = RiskScoringEngine(ScoringPolicyConfig())

    tp = 0  # True Positives: Malicious correctly flagged as BLOCK or WARN
    fp = 0  # False Positives: Benign incorrectly flagged as BLOCK or WARN
    tn = 0  # True Negatives: Benign correctly flagged as ALLOW
    fn = 0  # False Negatives: Malicious missed and flagged as ALLOW

    for record in report.accepted_records:
        raw_url = record["raw_input"]
        ground_truth = record["label"]

        try:
            norm = URLNormalizer.normalize(raw_url)
            # Synchronous cache check for evaluation
            v_hashes = [norm.url_sha256, norm.domain_sha256]
            matches = [repo._LOCAL_CACHE[h] for h in v_hashes if h in repo._LOCAL_CACHE]

            evidence = analyzer.analyze(norm)
            is_whitelisted = analyzer._is_whitelisted(norm)
            outcome = scoring_engine.evaluate(
                indicator_matches=matches,
                heuristic_evidence=evidence,
                is_whitelisted=is_whitelisted,
            )

            predicted_malicious = outcome.decision in {"block", "warn"}

            if ground_truth in {"malicious", "suspicious"}:
                if predicted_malicious:
                    tp += 1
                else:
                    fn += 1
            elif ground_truth == "benign":
                if predicted_malicious:
                    fp += 1
                else:
                    tn += 1

        except Exception as e:
            print(f"Error evaluating '{raw_url}': {e}")
            fn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("Confusion Matrix:")
    print(f"  True Positives (TP):  {tp}")
    print(f"  False Positives (FP): {fp}")
    print(f"  True Negatives (TN):  {tn}")
    print(f"  False Negatives (FN): {fn}\n")

    print("Performance Metrics:")
    print(f"  Accuracy:            {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"  Precision:           {precision:.4f} ({precision * 100:.2f}%)")
    print(f"  Recall (Detection):  {recall:.4f} ({recall * 100:.2f}%)")
    print(f"  F1 Score:            {f1:.4f}")
    print(f"  False Positive Rate: {fpr:.4f} ({fpr * 100:.2f}%)\n")

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate threat detection engine against labeled dataset."
    )
    parser.add_argument(
        "--dataset",
        default="datasets/manifests/synthetic_url_dataset.json",
        help="Path to CSV or JSON dataset manifest",
    )
    args = parser.parse_args()
    evaluate_dataset(args.dataset)
