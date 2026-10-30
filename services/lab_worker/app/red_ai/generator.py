"""Deterministic and AI-augmented Scenario Generator for synthetic threat scenarios.

Generates reproducible scenario corpora given a random seed, goal, and configuration parameters.
Supports:
1. QwenProvider integration for realistic, model-synthesized scenarios.
2. Deterministic ThreatPatternLibrary and ScenarioMutationEngine for offline procedural baselines.

SAFETY INVARIANTS:
- All generated URLs MUST strictly terminate in RFC 2606 reserved domains (.test, .example).
- Unexpected live domains are rejected and blocked.
- Fails closed in production: No silent procedural fallback when Qwen fails.
"""

from __future__ import annotations

import logging
import os
import random
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from cyberduel_contracts.enums import ScenarioFamily
from cyberduel_contracts.lab import ScenarioContract

from services.lab_worker.app.red_ai.mutator import ScenarioMutationEngine
from services.lab_worker.app.red_ai.patterns import ThreatPatternLibrary

try:
    from apps.api.app.core.config import get_settings
    from apps.api.app.providers.base import (
        ProviderError,
        ProviderInferenceError,
        ProviderUnavailableError,
    )
    from apps.api.app.providers.factory import get_ai_provider
except ImportError:
    get_settings = None  # type: ignore
    get_ai_provider = None  # type: ignore
    ProviderError = Exception  # type: ignore
    ProviderInferenceError = Exception  # type: ignore
    ProviderUnavailableError = Exception  # type: ignore

logger = logging.getLogger("red_scenario_generator")
RFC_2606_TLDS = (".test", ".example", ".invalid", ".localhost")


class ScenarioGenerator:
    """Orchestrates generation of synthetic threat scenarios via Qwen or procedural templates."""

    GENERATOR_VERSION = "red-generator-1.0.0"

    def __init__(
        self,
        seed: int = 42,
        provider: Any | None = None,
        provider_mode: str | None = None,
    ) -> None:
        self.seed = seed
        self._rng = random.Random(seed)
        self.mutation_engine = ScenarioMutationEngine(seed=seed)

        # Resolve provider mode from argument, settings, or environment
        if provider_mode:
            self.provider_mode = provider_mode
        elif get_settings:
            try:
                self.provider_mode = get_settings().AI_PROVIDER_TYPE
            except Exception:
                self.provider_mode = os.getenv("AI_PROVIDER_TYPE", "procedural")
        else:
            self.provider_mode = os.getenv("AI_PROVIDER_TYPE", "procedural")

        self.provider = provider
        if not self.provider and self.provider_mode == "qwen" and get_ai_provider:
            try:
                self.provider = get_ai_provider("qwen")
            except Exception as exc:
                logger.warning(f"Could not initialize QwenProvider in ScenarioGenerator: {exc}")
                self.provider = None

    def _is_safe_rfc2606_url(self, raw_url: str) -> bool:
        """Enforce strict RFC 2606 reserved domain boundaries on all generated scenarios."""
        try:
            parsed = urlparse(raw_url)
            host = (parsed.hostname or "").lower()
            if not host:
                return False
            return any(host == tld.lstrip(".") or host.endswith(tld) for tld in RFC_2606_TLDS)
        except Exception:
            return False

    async def generate_corpus_async(
        self,
        count: int = 100,
        families: list[ScenarioFamily | str] | None = None,
        mutation_depth: int = 1,
        goal: str = "general_exploration",
        experiment_id: UUID | None = None,
    ) -> list[ScenarioContract]:
        """Generate scenario corpus asynchronously, using Qwen if configured or procedural fallback."""
        if self.provider_mode == "qwen":
            if not self.provider:
                is_prod = (get_settings().is_production if get_settings else False) or (
                    os.getenv("ENVIRONMENT") == "production"
                )
                if is_prod:
                    raise ProviderUnavailableError(
                        "Production mode requires active QwenProvider; silent fallback prohibited."
                    )
                logger.warning(
                    "Qwen provider requested but not initialized; falling back to procedural mode."
                )
                return self.generate_corpus(
                    count=count, families=families, mutation_depth=mutation_depth, goal=goal
                )

            try:
                scenarios: list[ScenarioContract] = []
                # Resolve target families
                all_families = [
                    f.value if isinstance(f, ScenarioFamily) else str(f)
                    for f in (
                        families
                        or [
                            ScenarioFamily.HOMOGLYPH_MIMICRY,
                            ScenarioFamily.CREDENTIAL_HARVESTING,
                            ScenarioFamily.SUBDOMAIN_FLOODING,
                            ScenarioFamily.BRAND_IMPERSONATION,
                        ]
                    )
                ]

                # Generate via Qwen up to count (or batch of unique scenarios)
                target_count = min(
                    count, 5
                )  # Cap LLM generations per single experiment cycle for latency bounds
                for i in range(target_count):
                    fam = all_families[i % len(all_families)]
                    sc = await self.provider.generate_scenario_contract(
                        target_family=fam,
                        goal=goal,
                        difficulty="intermediate",
                        seed=self.seed + i,
                        experiment_id=experiment_id,
                    )
                    # Verify RFC 2606 safety
                    url = sc.input_fixture.get("raw_url", "")
                    if not self._is_safe_rfc2606_url(url):
                        raise ProviderInferenceError(
                            f"Safety violation: Qwen generated live domain '{url}'. "
                            "Scenarios must strictly use RFC 2606 reserved domains (.test, .example)."
                        )
                    scenarios.append(sc)

                # If more scenarios are requested than LLM batch, apply mutations to Qwen base scenarios
                if len(scenarios) < count:
                    idx = 0
                    while len(scenarios) < count and idx < len(scenarios):
                        base = scenarios[idx]
                        idx += 1
                        mut = self.mutation_engine.mutate(base, max_depth=mutation_depth)
                        # Verify mutated URL remains in safe domain
                        if self._is_safe_rfc2606_url(mut.input_fixture.get("raw_url", "")):
                            scenarios.append(mut)

                logger.info(
                    "Successfully synthesized %d scenarios via QwenProvider.", len(scenarios)
                )
                return scenarios

            except Exception as exc:
                is_prod = (get_settings().is_production if get_settings else False) or (
                    os.getenv("ENVIRONMENT") == "production"
                )
                if is_prod:
                    raise ProviderInferenceError(
                        f"Qwen scenario generation failed in production: {exc}"
                    ) from exc
                logger.error(f"Qwen scenario generation failed: {exc}. Failing closed per policy.")
                raise

        # Procedural generation mode
        return self.generate_corpus(
            count=count, families=families, mutation_depth=mutation_depth, goal=goal
        )

    def generate_corpus(
        self,
        count: int = 100,
        families: list[ScenarioFamily | str] | None = None,
        mutation_depth: int = 1,
        goal: str = "general_exploration",
    ) -> list[ScenarioContract]:
        """Generate a deterministic corpus of valid ScenarioContract objects using procedural templates."""
        # 1. Resolve family filter
        all_templates = ThreatPatternLibrary.list_templates()
        if families:
            family_strs = {f.value if isinstance(f, ScenarioFamily) else str(f) for f in families}
            templates = [t for t in all_templates if t.family.value in family_strs]
            if not templates:
                templates = all_templates
        else:
            templates = all_templates

        corpus: list[ScenarioContract] = []
        seen_urls: set[str] = set()

        # 2. First pass: Instantiate base templates deterministically
        for tmpl in templates:
            if len(corpus) >= count:
                break

            scenario = ScenarioContract(
                scenario_id=uuid4(),
                schema_version="1.0.0",
                scenario_family=tmpl.family.value,
                scenario_name=tmpl.name,
                description=tmpl.description,
                expected_class=tmpl.expected_class.value,
                expected_decision=tmpl.expected_decision,
                difficulty=tmpl.difficulty,  # type: ignore[arg-type]
                tags=list(tmpl.tags),
                seed=self.seed,
                generator_version=f"{self.GENERATOR_VERSION}-procedural",
                mutation_parent_id=None,
                transformation_history=[],
                input_fixture={"raw_url": tmpl.raw_url},
                expected_evidence=list(tmpl.expected_evidence),
                provenance={
                    "origin": "ThreatPatternLibrary",
                    "mode": "procedural",
                    "template_id": tmpl.template_id,
                    "rationale": tmpl.rationale,
                    "goal": goal,
                    "seed": self.seed,
                },
                safety_classification="harmless_synthetic",
            )
            corpus.append(scenario)
            seen_urls.add(tmpl.raw_url)

        # 3. Second pass: Generate mutated variations if count > len(templates)
        idx = 0
        while len(corpus) < count and idx < len(corpus):
            base_scenario = corpus[idx]
            idx += 1

            for _depth in range(max(1, mutation_depth)):
                if len(corpus) >= count:
                    break

                mutated = self.mutation_engine.mutate(base_scenario, max_depth=5)
                raw_url = str(mutated.input_fixture.get("raw_url", ""))
                if raw_url not in seen_urls:
                    seen_urls.add(raw_url)
                    corpus.append(mutated)
                    base_scenario = mutated

        # 4. If count still not met, synthesize parameter variations with distinct seeds
        while len(corpus) < count:
            sample_tmpl = self._rng.choice(templates)
            pert_num = self._rng.randint(1000, 99999)
            pert_url = (
                f"{sample_tmpl.raw_url}"
                f"{'&' if '?' in sample_tmpl.raw_url else '?'}variant={pert_num}"
            )
            if pert_url in seen_urls:
                continue
            seen_urls.add(pert_url)

            scenario = ScenarioContract(
                scenario_id=uuid4(),
                schema_version="1.0.0",
                scenario_family=sample_tmpl.family.value,
                scenario_name=f"{sample_tmpl.name} (Variant {pert_num})",
                description=f"{sample_tmpl.description} [Variant seed {pert_num}]",
                expected_class=sample_tmpl.expected_class.value,
                expected_decision=sample_tmpl.expected_decision,
                difficulty=sample_tmpl.difficulty,  # type: ignore[arg-type]
                tags=list(sample_tmpl.tags),
                seed=pert_num,
                generator_version=f"{self.GENERATOR_VERSION}-procedural",
                mutation_parent_id=None,
                transformation_history=[],
                input_fixture={"raw_url": pert_url},
                expected_evidence=list(sample_tmpl.expected_evidence),
                provenance={
                    "origin": "ThreatPatternLibrary",
                    "mode": "procedural",
                    "template_id": sample_tmpl.template_id,
                    "rationale": sample_tmpl.rationale,
                    "variant_seed": pert_num,
                    "goal": goal,
                },
                safety_classification="harmless_synthetic",
            )
            corpus.append(scenario)

        return corpus
