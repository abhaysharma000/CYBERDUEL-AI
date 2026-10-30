"""Dataset ingestion, normalization, and validation engine for labeled threat corpora."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberduel_threat_intel.validator import URLValidator


@dataclass
class DatasetIngestionReport:
    """Detailed audit metrics of a dataset ingestion run."""

    file_path: str
    rows_read: int = 0
    rows_accepted: int = 0
    rows_rejected: int = 0
    duplicate_records: int = 0
    missing_labels: int = 0
    invalid_urls: int = 0
    label_distribution: dict[str, int] = field(default_factory=dict)
    rejected_reasons: list[str] = field(default_factory=list)
    accepted_records: list[dict[str, Any]] = field(default_factory=list)


class DatasetIngestionEngine:
    """Parses, validates, and normalizes URL threat datasets from CSV and JSON formats."""

    DEFAULT_COLUMN_MAPPING = {
        "url": ["url", "URL", "domain", "Domain", "link", "address"],
        "label": ["label", "Label", "class", "target", "status", "category"],
        "source": ["source", "Source", "feed", "dataset"],
        "timestamp": ["timestamp", "observed_at", "date", "time"],
    }

    @classmethod
    def ingest_file(
        cls,
        file_path: str | Path,
        custom_mapping: dict[str, str] | None = None,
    ) -> DatasetIngestionReport:
        """Ingest and validate a CSV or JSON dataset with idempotent deduplication."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Dataset file not found: {path}")

        report = DatasetIngestionReport(file_path=str(path))
        label_counter: Counter[str] = Counter()
        seen_identifiers: set[str] = set()

        raw_rows: list[dict[str, Any]] = []

        if path.suffix.lower() == ".json":
            with open(path, encoding="utf-8") as f:
                content = json.load(f)
                if isinstance(content, list):
                    raw_rows = content
                elif isinstance(content, dict) and "records" in content:
                    raw_rows = content["records"]
                elif isinstance(content, dict) and "data" in content:
                    raw_rows = content["data"]
                else:
                    raise ValueError(
                        "JSON dataset must be a list of records or contain a 'records' key."
                    )
        elif path.suffix.lower() == ".csv":
            with open(path, encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                raw_rows = list(reader)
        else:
            raise ValueError(
                f"Unsupported dataset format: {path.suffix}. Only .json and .csv supported."
            )

        report.rows_read = len(raw_rows)

        for idx, row in enumerate(raw_rows):
            # 1. Resolve column names
            url_val = cls._resolve_field(row, "url", custom_mapping)
            label_val = cls._resolve_field(row, "label", custom_mapping)
            source_val = cls._resolve_field(row, "source", custom_mapping) or path.stem

            if not url_val:
                report.rows_rejected += 1
                report.invalid_urls += 1
                if len(report.rejected_reasons) < 20:
                    report.rejected_reasons.append(f"Row {idx}: missing URL field")
                continue

            # 2. Validate URL structure
            validation = URLValidator.validate(url_val)
            if not validation.is_valid or not validation.normalized:
                report.rows_rejected += 1
                report.invalid_urls += 1
                if len(report.rejected_reasons) < 20:
                    report.rejected_reasons.append(
                        f"Row {idx}: invalid URL '{url_val[:40]}' ({validation.error_code})"
                    )
                continue

            normalized = validation.normalized

            # 3. Validate and normalize Label
            if not label_val:
                report.rows_rejected += 1
                report.missing_labels += 1
                if len(report.rejected_reasons) < 20:
                    report.rejected_reasons.append(f"Row {idx}: missing label")
                continue

            normalized_label = cls._canonical_label(label_val)
            if not normalized_label:
                report.rows_rejected += 1
                report.missing_labels += 1
                if len(report.rejected_reasons) < 20:
                    report.rejected_reasons.append(f"Row {idx}: unrecognized label '{label_val}'")
                continue

            # 4. Idempotent Deduplication (by normalized URL hash)
            if normalized.url_sha256 in seen_identifiers:
                report.duplicate_records += 1
                continue

            seen_identifiers.add(normalized.url_sha256)
            report.rows_accepted += 1
            label_counter[normalized_label] += 1

            record = {
                "normalized_url": normalized.canonical_url,
                "url_sha256": normalized.url_sha256,
                "domain": normalized.domain,
                "domain_sha256": normalized.domain_sha256,
                "label": normalized_label,
                "source": source_val,
                "raw_input": url_val,
            }
            report.accepted_records.append(record)

        report.label_distribution = dict(label_counter)
        return report

    @classmethod
    def _resolve_field(
        cls, row: dict[str, Any], field_key: str, custom_mapping: dict[str, str] | None
    ) -> str | None:
        if custom_mapping and field_key in custom_mapping:
            target_col = custom_mapping[field_key]
            val = row.get(target_col)
            return str(val).strip() if val is not None else None

        candidates = cls.DEFAULT_COLUMN_MAPPING.get(field_key, [field_key])
        for c in candidates:
            if c in row and row[c] is not None:
                val = str(row[c]).strip()
                if val:
                    return val
        return None

    @classmethod
    def _canonical_label(cls, raw_label: str) -> str | None:
        clean = raw_label.strip().lower()
        if clean in {"1", "malicious", "phishing", "malware", "bad", "spam", "fraud"}:
            return "malicious"
        if clean in {"0", "benign", "clean", "safe", "legitimate", "good"}:
            return "benign"
        if clean in {"suspicious", "warn", "grey", "unknown"}:
            return "suspicious"
        return None
