# CyberDuel AI — Datasets and Scenario Manifests

## Purpose & Manifest Directory

This directory stores reproducible evaluation manifests, synthetic threat corpora, and baseline golden benchmarks used by the Independent Evaluation Engine.

### Data Governance Rules:
1. **No Live Exploit Binaries:** All datasets must contain declarative feature representations, JSON scenario specifications, or synthetic domain strings.
2. **Privacy Standards:** No raw user browsing histories, private customer URLs, or PII are stored here.
3. **Reproducibility:** Every evaluation run references an exact Git-tracked manifest ID or hash.

### Manifest Layout:
- `manifests/golden_phishing_v1.json`: Curated ground-truth phishing lures.
- `manifests/golden_benign_v1.json`: Top 10,000 Alexa/Tranco domains for false-positive validation.
- `manifests/adversarial_homoglyphs_v1.json`: Synthetic IDN homograph scenarios.

