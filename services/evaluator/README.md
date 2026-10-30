# CyberDuel AI — Independent Benchmark Evaluator

## Subsystem Role

The Independent Evaluator is the architectural gatekeeper of the CyberDuel platform:
> **The research laboratory may experiment continuously; production defenses change only after independent validation and controlled release.**

The Evaluator tests proposed candidate defenses developed by Blue AI against fixed benchmark corpora and historic regression test suites.

### Gatekeeping Acceptance Criteria:
- **Zero Known Regressions:** A candidate defense must never break detection of known benign services.
- **Strict False-Positive Rate:** Must not exceed calibrated false-positive thresholds (typically $< 0.05\%$).
- **Resource Overhead Budget:** Must complete inspections within acceptable CPU and memory limits.

---

## Current Status (Phase 1)

In Phase 1, the Evaluator provides the core mathematical interfaces, schemas (`EvaluationResult`), and deterministic benchmark evaluation tests.

---

## Local Testing

```bash
pytest services/evaluator/tests
```

