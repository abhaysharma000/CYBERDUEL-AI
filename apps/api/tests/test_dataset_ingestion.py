"""Tests for dataset ingestion, parsing, and validation."""

import json
from pathlib import Path

from cyberduel_threat_intel.dataset import DatasetIngestionEngine


def test_ingest_synthetic_json_dataset() -> None:
    path = "datasets/manifests/synthetic_url_dataset.json"
    report = DatasetIngestionEngine.ingest_file(path)
    assert report.rows_read == 15
    assert report.rows_accepted == 15
    assert report.rows_rejected == 0
    assert report.duplicate_records == 0
    assert report.label_distribution["benign"] == 7
    assert report.label_distribution["malicious"] == 6
    assert report.label_distribution["suspicious"] == 2


def test_ingest_csv_dataset(tmp_path: Path) -> None:
    csv_file = tmp_path / "test_feed.csv"
    csv_content = """address,status,feed_name
https://example.com/clean,safe,feed_alpha
https://bad-phish.xyz/login,malicious,feed_alpha
https://example.com/clean,safe,feed_alpha
invalid_url_without_scheme,bad,feed_alpha
https://missing-label.org/page,,feed_alpha
"""
    csv_file.write_text(csv_content, encoding="utf-8")

    report = DatasetIngestionEngine.ingest_file(
        csv_file,
        custom_mapping={"url": "address", "label": "status", "source": "feed_name"},
    )
    assert report.rows_read == 5
    assert report.rows_accepted == 2  # 2 unique valid rows
    assert report.duplicate_records == 1  # 1 duplicate
    assert report.rows_rejected == 2  # 1 malformed URL, 1 missing label
    assert report.invalid_urls == 1
    assert report.missing_labels == 1


def test_deduplication_idempotency(tmp_path: Path) -> None:
    json_file = tmp_path / "dups.json"
    data = [
        {"url": "https://test.com/a", "label": "benign"},
        {"url": "https://test.com/a", "label": "benign"},
        {"url": "https://test.com/a", "label": "benign"},
    ]
    json_file.write_text(json.dumps(data), encoding="utf-8")
    report = DatasetIngestionEngine.ingest_file(json_file)
    assert report.rows_read == 3
    assert report.rows_accepted == 1
    assert report.duplicate_records == 2
