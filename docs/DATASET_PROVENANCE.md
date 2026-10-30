# CyberDuel AI — Security Dataset Provenance and Integrity Specification

## 1. Executive Summary

This document establishes the provenance, licensing, ethical handling, partitioning methodology, and cryptographic integrity hashes for the security datasets used by CyberDuel AI.

In accordance with our architecture integrity principles:
1. All datasets are legally sourced, open-access, and attributed.
2. URLs and threat indicators are stored and handled strictly as inert text strings.
3. Live network resolution, DNS lookups, and active scraping are strictly forbidden.
4. Splits are partitioned by registrable domain to guarantee zero cross-split domain leakage.
5. The held-out test split is cryptographically sealed and isolated from training and threshold tuning.

---

## 2. Dataset Provenance, Licensing & Legal Invariants

> [!CAUTION]
> **Provenance & Licensing Reality:**
> - Neither ISCX-URL2016 nor OpenPhish is Public Domain.
> - The current 50-record corpus is a **Curated Pilot Research Fixture** designed strictly for integration testing, schema validation, and defensive rule formulation.
> - **No full upstream dataset ingestion has occurred.** It is an unverified pilot subset.
> - OpenPhish-derived indicators are strictly restricted to non-commercial evaluation and are **excluded from commercial or production training claims**.

| Source / Component | Provider / Institution | License / Usage Terms | Public Domain? | Commercial Training Permitted? | Role in CyberDuel AI |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **ISCX-URL2016 (Subset)** | Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB) | Non-Commercial Academic & Research Use Only (Citation required: A. H. Mamun et al., 2016). | **NO** | **NO** | Curated benign URLs and credential harvesting patterns for pilot evaluation. |
| **OpenPhish Public Feed (Subset)** | OpenPhish Research Community | Limited non-commercial research inspection. Redistribution and commercial model training prohibited. | **NO** | **NO** | Pilot attack vector signatures for lexical testing only. Excluded from product training. |
| **Synthetic Control Vectors** | CyberDuel AI Research Laboratory | Apache 2.0 / Internal Research | N/A (Synthetic) | **YES** (Internal synthetic logic) | Safe RFC 2606 reserved domains (`.test`, `.example`, `.invalid`) for controlled adversarial testing. |

### Ethical and Safe Handling Rules
- **No Payload Hosting:** No executable binaries, exploit payloads, or malicious scripts are stored in the repository.
- **Inert Text Storage:** URLs are recorded strictly as inert text strings for lexical feature extraction and AST rule training.
- **No Active Crawling:** Backend services and AI pipelines must never issue HTTP requests to sample URLs.
- **Defanged Reporting:** All documentation and logs must defang schemes (`hxxp://`, `hxxps://`) and dot delimiters (`[.]`) to prevent accidental user clicks.

---

## 3. Domain-Grouped Partitioning Methodology

### The Domain Leakage Vulnerability
Standard random URL-level splitting allows subdomains and paths of the same root domain to appear in both training and test sets. When models memorize the root domain, benchmark scores become artificially inflated and fail to generalize.

### Partitioning Algorithm
To prevent leakage, CyberDuel AI employs **registrable domain grouping**:
1. Every URL is normalized and parsed to its registrable domain (eTLD+1).
2. The corpus is grouped by unique domain into distinct domain buckets.
3. Buckets are distributed across splits targeting a 60% Train / 20% Validation / 20% Held-Out ratio while maintaining label balance.
4. **Zero-Leakage Invariant:**
   $$\text{Domains}(D_{\text{train}}) \cap \text{Domains}(D_{\text{val}}) = \emptyset$$
   $$\text{Domains}(D_{\text{train}}) \cap \text{Domains}(D_{\text{test}}) = \emptyset$$
   $$\text{Domains}(D_{\text{val}}) \cap \text{Domains}(D_{\text{test}}) = \emptyset$$

---

## 4. Corpus Statistics and Cryptographic Hashes

Generated on: **2026-10-29T17:56:00Z**  
Pipeline script: `scripts/dataset_pipeline.py`  
Manifest file: `datasets/manifests/dataset_manifest.json`

| Split | Relative Path | Record Count | Unique Domains | Phishing | Benign | SHA-256 Digest |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Train** | `datasets/splits/train.jsonl` | 30 | 29 | 17 | 13 | `d2c66a3d61c2ac3ee5d3242242e914c82daabf213a1ead62d4fc9a94e330e2eb` |
| **Validation** | `datasets/splits/val.jsonl` | 10 | 10 | 3 | 7 | `8d5f7c9a85df16853eabf2c364d07733f59db5210bc9daf3b915d808d1d973e2` |
| **Held-Out Test** | `datasets/splits/test_held_out.jsonl` | 10 | 10 | 5 | 5 | `92071081c1f75866dfd3364aa796803eddeae9ca657731036aa1b71c3db23e34` |
| **Total** | `datasets/raw/security_urls_raw.jsonl` | 50 | 49 | 25 | 25 | *(Curated raw corpus)* |

---

## 5. Held-Out Test Set Isolation Protocol

The held-out test set (`datasets/splits/test_held_out.jsonl`) evaluates model generalization and defense candidate effectiveness.

### Enforcement Rules
1. **Never in Training:** Neither `scripts/generate_agent_tasks.py` nor `scripts/train_qwen_lora.py` may open, read, or process `test_held_out.jsonl`.
2. **Programmatic Assertion:** Both scripts include automated runtime checks that raise `PermissionError` if `test_held_out.jsonl` is supplied in paths or arguments.
3. **Automated CI Tests:** Integration tests (`tests/integration/test_dataset_and_qwen_pipeline.py`) verify that isolation guards cannot be bypassed.
4. **Independent Evaluator Sole Custody:** Only the deterministic `EvaluationEngine` may ingest the held-out test set during post-training candidate benchmark evaluation.

---

## 6. Verification and Reproduction

To reproduce the dataset pipeline and verify checksums:

```powershell
# In PowerShell:
.venv\Scripts\python.exe scripts/dataset_pipeline.py
Get-FileHash -Algorithm SHA256 datasets/splits/*.jsonl
```

