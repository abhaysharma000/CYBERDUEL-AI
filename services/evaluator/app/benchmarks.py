"""Benchmark suite registry and leakage-resistant dataset manager for independent evaluation."""

import hashlib
import json
import logging
from pathlib import Path
from uuid import UUID, uuid5

from cyberduel_contracts.enums import (
    DatasetSplitType,
    Decision,
    ExpectedClass,
    ScenarioFamily,
)
from cyberduel_contracts.evaluation import BenchmarkManifest, BenchmarkScenarioItem

logger = logging.getLogger("evaluator.benchmarks")

_NAMESPACE_BENCHMARK = UUID("d86e1150-1c32-473d-9d7b-9f939e6587c1")


class BenchmarkRegistry:
    """Registry maintaining standardized benchmark manifests with group isolation checks."""

    def __init__(self, storage_dir: Path | str | None = None) -> None:
        self.storage_dir = Path(storage_dir) if storage_dir else None
        self._manifests: dict[str, BenchmarkManifest] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Register the built-in standard golden benchmark manifest."""
        golden = self.create_default_golden_manifest()
        self.register_manifest(golden)

    def register_manifest(self, manifest: BenchmarkManifest) -> None:
        """Register a verified benchmark manifest."""
        is_isolated, violations = self.validate_split_isolation(manifest)
        if not is_isolated:
            raise ValueError(
                f"Benchmark manifest {manifest.manifest_id} failed group isolation: {violations}"
            )
        self._manifests[manifest.manifest_id] = manifest
        logger.info(
            f"Registered benchmark manifest '{manifest.manifest_id}' (v{manifest.version}) "
            f"with {manifest.scenario_count} scenarios across {len(manifest.split_counts)} splits"
        )

    def get_manifest(self, manifest_id: str) -> BenchmarkManifest | None:
        """Retrieve a benchmark manifest by ID or version."""
        if manifest_id in self._manifests:
            return self._manifests[manifest_id]
        if manifest_id in {"curated-golden-v1", "default", "golden", "latest"}:
            return self._manifests.get("benchmark-golden-v1")
        for m in self._manifests.values():
            if m.version == manifest_id or m.name == manifest_id:
                return m
        return None

    def list_manifests(self) -> list[BenchmarkManifest]:
        """List all registered benchmark manifests."""
        return list(self._manifests.values())

    @staticmethod
    def compute_integrity_hash(scenarios: list[BenchmarkScenarioItem]) -> str:
        """Compute deterministic SHA-256 digest over normalized benchmark scenarios."""
        hasher = hashlib.sha256()
        for sc in sorted(scenarios, key=lambda s: str(s.scenario_id)):
            record = (
                f"{sc.scenario_id}:{sc.url}:{sc.expected_class.value}:"
                f"{sc.expected_decision.value}:{sc.split.value}:{sc.group_id}"
            )
            hasher.update(record.encode("utf-8"))
        return hasher.hexdigest()

    @staticmethod
    def validate_split_isolation(manifest: BenchmarkManifest) -> tuple[bool, list[str]]:
        """Verify strict isolation and zero data leakage across training and evaluation splits.

        Rules:
        1. No identical URL can appear in multiple splits.
        2. No group_id (lineage/domain) can overlap between training/development and held-out/regression.
        """
        violations: list[str] = []
        urls_by_split: dict[str, set[str]] = {}
        groups_by_split: dict[str, set[str]] = {}

        for item in manifest.scenarios:
            split_key = item.split.value
            urls_by_split.setdefault(split_key, set())
            groups_by_split.setdefault(split_key, set())

            norm_url = item.url.strip().lower()
            urls_by_split[split_key].add(norm_url)
            groups_by_split[split_key].add(item.group_id)

        # Check URL duplication across any distinct splits
        all_splits = list(urls_by_split.keys())
        for i in range(len(all_splits)):
            for j in range(i + 1, len(all_splits)):
                s1, s2 = all_splits[i], all_splits[j]
                overlap = urls_by_split[s1].intersection(urls_by_split[s2])
                if overlap:
                    violations.append(
                        f"URL leakage between split '{s1}' and '{s2}': {list(overlap)[:3]}"
                    )

        # Check group leakage between development/validation and held_out/regression
        training_splits = {
            DatasetSplitType.DEVELOPMENT.value,
            DatasetSplitType.VALIDATION.value,
        }
        eval_splits = {
            DatasetSplitType.HELD_OUT.value,
            DatasetSplitType.REGRESSION.value,
        }

        train_groups: set[str] = set()
        for s in training_splits:
            train_groups.update(groups_by_split.get(s, set()))

        eval_groups: set[str] = set()
        for s in eval_splits:
            eval_groups.update(groups_by_split.get(s, set()))

        group_overlap = train_groups.intersection(eval_groups)
        if group_overlap:
            violations.append(
                f"Group/lineage leakage between training and held-out/regression: {list(group_overlap)}"
            )

        return (len(violations) == 0, violations)

    @classmethod
    def create_default_golden_manifest(cls) -> BenchmarkManifest:
        """Create a diverse, standardized golden benchmark manifest for independent evaluation."""
        raw_items: list[dict[str, object]] = [
            # --- BENIGN CONTROLS (benign_control split) ---
            {
                "url": "https://www.google.com/search?q=cybersecurity",
                "class": ExpectedClass.BENIGN,
                "decision": Decision.ALLOW,
                "family": ScenarioFamily.WHITELIST_CONTROL.value,
                "split": DatasetSplitType.BENIGN_CONTROL,
                "group": "group_benign_google",
            },
            {
                "url": "https://github.com/torvalds/linux",
                "class": ExpectedClass.BENIGN,
                "decision": Decision.ALLOW,
                "family": ScenarioFamily.WHITELIST_CONTROL.value,
                "split": DatasetSplitType.BENIGN_CONTROL,
                "group": "group_benign_github",
            },
            {
                "url": "https://docs.python.org/3/library/urllib.parse.html",
                "class": ExpectedClass.BENIGN,
                "decision": Decision.ALLOW,
                "family": ScenarioFamily.WHITELIST_CONTROL.value,
                "split": DatasetSplitType.BENIGN_CONTROL,
                "group": "group_benign_python",
            },
            {
                "url": "https://en.wikipedia.org/wiki/Transport_Layer_Security",
                "class": ExpectedClass.BENIGN,
                "decision": Decision.ALLOW,
                "family": ScenarioFamily.WHITELIST_CONTROL.value,
                "split": DatasetSplitType.BENIGN_CONTROL,
                "group": "group_benign_wiki",
            },
            {
                "url": "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array",
                "class": ExpectedClass.BENIGN,
                "decision": Decision.ALLOW,
                "family": ScenarioFamily.WHITELIST_CONTROL.value,
                "split": DatasetSplitType.BENIGN_CONTROL,
                "group": "group_benign_so",
            },
            # --- REGRESSION SUITE (regression split - frozen cases that must never break) ---
            {
                "url": "http://192.168.1.1/admin/login.php",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.IP_HOST.value,
                "split": DatasetSplitType.REGRESSION,
                "group": "group_reg_ip_private",
            },
            {
                "url": "http://203.0.113.15:8080/secure/banking/update",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.SUSPICIOUS_PORT.value,
                "split": DatasetSplitType.REGRESSION,
                "group": "group_reg_ip_port",
            },
            {
                "url": "https://pаypal.com/signin/verify-identity",  # Cyrillic 'а'
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.HOMOGRAPH_MIMICRY.value,
                "split": DatasetSplitType.REGRESSION,
                "group": "group_reg_homograph_paypal",
            },
            {
                "url": "https://login-microsoft-online.com/auth/login",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.BRAND_IMPERSONATION.value,
                "split": DatasetSplitType.REGRESSION,
                "group": "group_reg_brand_ms",
            },
            {
                "url": "https://chase-bank-verify-account-credential-portal.com/login",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.PHISHING_KEYWORDS.value,
                "split": DatasetSplitType.REGRESSION,
                "group": "group_reg_phish_chase",
            },
            # --- DEVELOPMENT SPLIT (development split - seen by Blue AI during prototyping) ---
            {
                "url": "http://198.51.100.42/payload.bin",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.IP_HOST.value,
                "split": DatasetSplitType.DEVELOPMENT,
                "group": "group_dev_ip_payload",
            },
            {
                "url": "https://gооgle.com/accounts/recovery",  # Cyrillic 'о'
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.HOMOGRAPH_MIMICRY.value,
                "split": DatasetSplitType.DEVELOPMENT,
                "group": "group_dev_homograph_google",
            },
            {
                "url": "https://apple-id-verify.support-desk99.com/unlock",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.BRAND_IMPERSONATION.value,
                "split": DatasetSplitType.DEVELOPMENT,
                "group": "group_dev_brand_apple",
            },
            {
                "url": "https://secure-auth-portal.com%252flogin?session=admin",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.DOUBLE_ENCODING.value,
                "split": DatasetSplitType.DEVELOPMENT,
                "group": "group_dev_double_encoding",
            },
            {
                "url": "https://a.b.c.d.e.f.g.h.subdomain-flood.org/page.html",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.SUBDOMAIN_FLOODING.value,
                "split": DatasetSplitType.DEVELOPMENT,
                "group": "group_dev_subdomain_flood",
            },
            # --- VALIDATION SPLIT (validation split - for intermediate pre-eval checks) ---
            {
                "url": "http://198.51.100.89:8443/cmd.exe",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.SUSPICIOUS_PORT.value,
                "split": DatasetSplitType.VALIDATION,
                "group": "group_val_port_cmd",
            },
            {
                "url": "https://netflix-account-reactivation-alert.net/billing",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.BRAND_IMPERSONATION.value,
                "split": DatasetSplitType.VALIDATION,
                "group": "group_val_brand_netflix",
            },
            {
                "url": "https://zkjdf98723kjnvd98234-dga-test.xyz/sync",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.DGA_ENTROPY.value,
                "split": DatasetSplitType.VALIDATION,
                "group": "group_val_dga",
            },
            {
                "url": "https://wellsfargo-secure-login-portal-credential.online/auth",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.PHISHING_KEYWORDS.value,
                "split": DatasetSplitType.VALIDATION,
                "group": "group_val_phish_wf",
            },
            # --- HELD-OUT SPLIT (held_out split - unseen evaluation for generalization testing) ---
            {
                "url": "http://203.0.113.99/unseen/malware.exe",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.IP_HOST.value,
                "split": DatasetSplitType.HELD_OUT,
                "group": "group_held_out_ip_exe",
            },
            {
                "url": "https://аmazon.com/ap/signin/order-status",  # Cyrillic 'а'
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.HOMOGRAPH_MIMICRY.value,
                "split": DatasetSplitType.HELD_OUT,
                "group": "group_held_out_homograph_amazon",
            },
            {
                "url": "https://dropbox-shared-document-download-center.top/file",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.BRAND_IMPERSONATION.value,
                "split": DatasetSplitType.HELD_OUT,
                "group": "group_held_out_brand_dropbox",
            },
            {
                "url": "https://qwx999plm888zxc111kjh444.biz/callback",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.DGA_ENTROPY.value,
                "split": DatasetSplitType.HELD_OUT,
                "group": "group_held_out_dga_biz",
            },
            {
                "url": "https://verified-bank-security-notice.com/confirm",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.PHISHING_KEYWORDS.value,
                "split": DatasetSplitType.HELD_OUT,
                "group": "group_held_out_phish_bank",
            },
            {
                "url": "https://internal-employee-vpn-portal.network/session",
                "class": ExpectedClass.MALICIOUS,
                "decision": Decision.BLOCK,
                "family": ScenarioFamily.BRAND_IMPERSONATION.value,
                "split": DatasetSplitType.HELD_OUT,
                "group": "group_held_out_vpn",
            },
        ]

        scenarios: list[BenchmarkScenarioItem] = []
        split_counts: dict[str, int] = {}
        family_counts: dict[str, int] = {}

        for item in raw_items:
            url_str = str(item["url"])
            sc_id = uuid5(_NAMESPACE_BENCHMARK, url_str)
            split_enum = item["split"]
            if not isinstance(split_enum, DatasetSplitType):
                raise TypeError("split must be DatasetSplitType")
            sc_item = BenchmarkScenarioItem(
                scenario_id=sc_id,
                url=url_str,
                expected_class=item["class"],  # type: ignore[arg-type]
                expected_decision=item["decision"],  # type: ignore[arg-type]
                scenario_family=str(item["family"]),
                split=split_enum,
                group_id=str(item["group"]),
                difficulty="intermediate",
                tags=[str(item["family"]), split_enum.value],
            )
            scenarios.append(sc_item)
            s_key = split_enum.value
            split_counts[s_key] = split_counts.get(s_key, 0) + 1
            f_key = str(item["family"])
            family_counts[f_key] = family_counts.get(f_key, 0) + 1

        integrity_hash = cls.compute_integrity_hash(scenarios)

        return BenchmarkManifest(
            manifest_id="benchmark-golden-v1",
            name="CyberDuel Golden Benchmark Suite v1",
            version="1.0.0",
            description="Verified multi-split benchmark suite with strict group isolation and zero label leakage",
            split_counts=split_counts,
            family_counts=family_counts,
            scenario_count=len(scenarios),
            scenarios=scenarios,
            integrity_hash=integrity_hash,
        )

    def save_manifest_to_disk(self, manifest: BenchmarkManifest, filepath: Path | str) -> None:
        """Persist a benchmark manifest as a JSON file."""
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(manifest.model_dump(mode="json"), f, indent=2)
        logger.info(f"Saved benchmark manifest '{manifest.manifest_id}' to {target}")

    def load_manifest_from_disk(self, filepath: Path | str) -> BenchmarkManifest:
        """Load and register a benchmark manifest from a JSON file."""
        target = Path(filepath)
        with open(target, encoding="utf-8") as f:
            data = json.load(f)
        manifest = BenchmarkManifest.model_validate(data)
        self.register_manifest(manifest)
        return manifest
