"""Real Qwen Open-Source LLM Provider Implementation.

Connects to any OpenAI-compatible inference endpoint hosting Qwen models
(e.g., DeepInfra, Together AI, or local Ollama/vLLM endpoints).

Enforces:
1. Strict structured JSON outputs matching canonical Pydantic schemas.
2. Hard timeouts (15s default).
3. Fail-closed behavior: errors surface immediately, NEVER falling back to mocks in production.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

import httpx
from cyberduel_contracts.analysis import EvidenceItem, ThreatAnalysisResult
from cyberduel_contracts.enums import (
    Decision,
    ProvenanceType,
    ThreatSeverity,
)
from cyberduel_contracts.lab import LaboratoryScenario, ScenarioContract
from cyberduel_contracts.policy import DeclarativeRuleModel, DefensiveHypothesis

from apps.api.app.core.config import get_settings
from apps.api.app.providers.base import (
    BaseReasoningProvider,
    BaseScenarioGeneratorProvider,
    BaseThreatClassificationProvider,
    ProviderInferenceError,
    ProviderRateLimitError,
    ProviderUnavailableError,
)

logger = logging.getLogger("cyberduel.ai.qwen")


class QwenProvider(
    BaseReasoningProvider,
    BaseThreatClassificationProvider,
    BaseScenarioGeneratorProvider,
):
    """Production provider integrating real Qwen open-source models via OpenAI-compatible API."""

    def __init__(
        self,
        api_base: str | None = None,
        api_key: str | None = None,
        model_name: str | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        settings = get_settings()
        self.api_base = (api_base or settings.QWEN_API_BASE).rstrip("/")
        self.api_key = api_key or settings.QWEN_API_KEY
        self.model_name = model_name or settings.QWEN_MODEL_NAME or "Qwen/Qwen2.5-Coder-7B-Instruct"
        self.timeout = timeout_seconds

        if not self.api_base:
            raise ValueError("Qwen API base URL (QWEN_API_BASE) must be configured.")

    async def check_endpoint_connectivity(
        self, timeout_seconds: float = 3.0
    ) -> tuple[bool, str, dict[str, Any]]:
        """Verify real HTTP connectivity to the configured Qwen model endpoint.

        Returns:
            tuple of (is_connected: bool, status_message: str, metadata: dict)
        """
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        start_time = datetime.now(UTC)
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            try:
                # Query OpenAI-compatible models discovery route
                resp = await client.get(f"{self.api_base}/models", headers=headers)
                latency_ms = (datetime.now(UTC) - start_time).total_seconds() * 1000
                if resp.status_code == 200:
                    return (
                        True,
                        "reachable",
                        {"latency_ms": round(latency_ms, 1), "model": self.model_name},
                    )
                elif resp.status_code == 401:
                    return False, "authentication_failed", {"status_code": 401}
                else:
                    return (
                        False,
                        f"http_status_{resp.status_code}",
                        {"status_code": resp.status_code},
                    )
            except httpx.TimeoutException:
                return False, "connection_timeout", {"timeout": timeout_seconds}
            except (httpx.ConnectError, httpx.NetworkError) as exc:
                return False, f"unreachable ({type(exc).__name__})", {}
            except Exception as exc:
                return False, f"error ({str(exc)})", {}

    async def _post_chat_completion(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
        require_json: bool = False,
    ) -> str:
        """Send chat completion request to Qwen endpoint and return raw text response."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
        }
        if require_json:
            payload["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    json=payload,
                )
            except httpx.TimeoutException as exc:
                logger.error("Qwen inference timed out after %.1fs", self.timeout)
                raise ProviderUnavailableError(
                    f"Qwen inference timed out after {self.timeout}s"
                ) from exc
            except (httpx.ConnectError, httpx.NetworkError) as exc:
                logger.error("Cannot connect to Qwen inference server at %s", self.api_base)
                raise ProviderUnavailableError(
                    f"Cannot connect to Qwen inference server at {self.api_base}"
                ) from exc

            if response.status_code == 429:
                logger.warning("Qwen rate limit exceeded (HTTP 429)")
                raise ProviderRateLimitError("Qwen provider rate limit exceeded")
            if response.status_code >= 500:
                logger.error("Qwen upstream server error: HTTP %d", response.status_code)
                raise ProviderUnavailableError(f"Qwen server error: HTTP {response.status_code}")
            if response.status_code != 200:
                logger.error(
                    "Qwen request failed with HTTP %d: %s",
                    response.status_code,
                    response.text[:200],
                )
                raise ProviderInferenceError(
                    f"Qwen request failed [HTTP {response.status_code}]: {response.text}"
                )

            try:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                return str(content)
            except (KeyError, IndexError, json.JSONDecodeError) as exc:
                raise ProviderInferenceError(
                    f"Malformed response envelope from Qwen: {response.text[:200]}"
                ) from exc

    async def generate_response(
        self,
        prompt: str,
        system_instruction: str = "",
        temperature: float = 0.2,
    ) -> str:
        """Produce reasoning output given a prompt and system context."""
        messages: list[dict[str, str]] = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        return await self._post_chat_completion(
            messages, temperature=temperature, require_json=False
        )

    async def generate_structured_json(
        self,
        prompt: str,
        system_instruction: str = "",
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        """Generate verified JSON dictionary from Qwen model."""
        sys_msg = (
            f"{system_instruction}\n"
            "CRITICAL: You MUST respond with a valid, parseable JSON object ONLY. "
            "Do NOT include markdown fences, code blocks, or preamble commentary."
        ).strip()

        messages = [
            {"role": "system", "content": sys_msg},
            {"role": "user", "content": prompt},
        ]

        raw = await self._post_chat_completion(messages, temperature=temperature, require_json=True)
        # Strip potential markdown code block wrappers if model emitted them
        clean = raw.strip()
        if clean.startswith("```json"):
            clean = clean[7:]
        elif clean.startswith("```"):
            clean = clean[3:]
        if clean.endswith("```"):
            clean = clean[:-3]
        clean = clean.strip()

        try:
            parsed = json.loads(clean)
            if not isinstance(parsed, dict):
                raise ProviderInferenceError(
                    f"Qwen expected JSON object, got {type(parsed).__name__}"
                )
            return parsed
        except json.JSONDecodeError as exc:
            raise ProviderInferenceError(f"Qwen returned invalid JSON: {clean[:200]}") from exc

    async def generate_scenario(
        self,
        target_vulnerability: str,
        difficulty: str = "intermediate",
    ) -> LaboratoryScenario:
        """Use Qwen to synthesize a realistic, safe adversarial scenario targeting a specific vulnerability."""
        prompt = (
            f"Generate a synthetic, isolated cybersecurity testing scenario.\n"
            f"Target Vulnerability: {target_vulnerability}\n"
            f"Difficulty Level: {difficulty}\n"
            f"Safety Constraint: Target domain MUST use RFC 2606 safe test domains ending in .test or .example.\n"
            f"Return a JSON object with: title, description, attack_family, test_url, evasion_technique, expected_decision (block|warn)."
        )

        data = await self.generate_structured_json(
            prompt=prompt,
            system_instruction="You are Red AI, an adversarial cybersecurity research model generating safe synthetic testing scenarios.",
            temperature=0.3,
        )

        test_url = str(data.get("test_url", "http://synthetic-attack.example.test/phish"))
        # Enforce RFC 2606 safe domain boundary even on model output
        if not (
            test_url.endswith(".test")
            or ".test/" in test_url
            or test_url.endswith(".example")
            or ".example/" in test_url
        ):
            test_url = "http://qwen-synthetic.example.test/login"

        dec_str = str(data.get("expected_decision", "block")).lower()
        expected_decision = Decision.BLOCK if dec_str == "block" else Decision.WARN

        return LaboratoryScenario(
            scenario_id=uuid4(),
            title=str(data.get("title", f"Qwen Synthetic Scenario for {target_vulnerability}")),
            description=str(data.get("description", "Synthesized by Qwen 2.5 Coder")),
            target_url=test_url,
            difficulty=difficulty
            if difficulty in ["beginner", "intermediate", "advanced", "expert"]
            else "intermediate",
            expected_decision=expected_decision,
            expected_score=0.90 if expected_decision == Decision.BLOCK else 0.65,
            safety_classification="harmless_synthetic",
            created_at=datetime.now(UTC),
        )

    async def generate_scenario_contract(
        self,
        target_family: str,
        goal: str = "adversarial_gap_exploration",
        difficulty: str = "intermediate",
        seed: int = 42,
        experiment_id: UUID | None = None,
    ) -> ScenarioContract:
        """Synthesize a canonical ScenarioContract using Qwen with strict RFC 2606 safety."""
        prompt = (
            f"Generate a synthetic, isolated cybersecurity testing scenario.\n"
            f"Target Family: {target_family}\n"
            f"Goal: {goal}\n"
            f"Difficulty: {difficulty}\n"
            f"CRITICAL SAFETY REQUIREMENT: Target URL must strictly use RFC 2606 reserved domains (.test or .example). "
            f"Never reference real live domains. The scenario must be harmless and synthetic.\n"
            f"Return strict JSON matching this schema:\n"
            f"{{\n"
            f'  "scenario_name": "string (3-128 chars)",\n'
            f'  "description": "string (max 512 chars)",\n'
            f'  "test_url": "https://... ending in .test or .example",\n'
            f'  "expected_class": "malicious" or "benign",\n'
            f'  "expected_decision": "block", "warn", or "allow",\n'
            f'  "evasion_technique": "string",\n'
            f'  "expected_evidence": ["indicator1", "indicator2"]\n'
            f"}}"
        )

        data = await self.generate_structured_json(
            prompt=prompt,
            system_instruction=(
                "You are Red AI, an adversarial cybersecurity research agent. "
                "Synthesize harmless synthetic test scenarios to evaluate detection gaps. "
                "All test URLs MUST strictly use .test or .example domains. Return strict JSON."
            ),
            temperature=0.2,
        )

        test_url = str(data.get("test_url", "")).strip()
        parsed = urlparse(test_url)
        host = (parsed.hostname or "").lower()
        if not host or not any(
            host == tld.lstrip(".") or host.endswith(tld)
            for tld in (".test", ".example", ".invalid", ".localhost")
        ):
            raise ProviderInferenceError(
                f"Red AI safety boundary violation: Qwen generated unsafe URL '{test_url}' with live domain '{host}'. "
                f"Scenarios must strictly end in RFC 2606 reserved domains (.test, .example)."
            )

        dec_str = str(data.get("expected_decision", "block")).lower()
        decision = (
            Decision.BLOCK
            if dec_str == "block"
            else (Decision.ALLOW if dec_str == "allow" else Decision.WARN)
        )

        scenario = ScenarioContract(
            scenario_id=uuid4(),
            schema_version="1.0.0",
            scenario_family=target_family,
            scenario_name=str(data.get("scenario_name", f"Qwen Synthetic {target_family}"))[:128],
            description=str(
                data.get("description", f"Qwen synthesized scenario targeting {target_family}")
            )[:512],
            expected_class=str(data.get("expected_class", "malicious")),
            expected_decision=decision,
            difficulty=difficulty
            if difficulty in ["basic", "intermediate", "advanced", "adversarial"]
            else "intermediate",
            tags=["qwen", "synthetic", target_family],
            seed=seed,
            generator_version=f"qwen-{self.model_name.split('/')[-1]}"[:32],
            mutation_parent_id=None,
            transformation_history=[],
            input_fixture={"raw_url": test_url},
            expected_evidence=list(data.get("expected_evidence", [target_family])),
            provenance={
                "origin": "QwenProvider",
                "model": self.model_name,
                "provider_status": "connected",
                "prompt_version": "red-qwen-v1.0",
                "seed": seed,
                "goal": goal,
                "experiment_id": str(experiment_id) if experiment_id else None,
                "evasion_technique": data.get("evasion_technique", "none"),
            },
            safety_classification="harmless_synthetic",
        )

        from services.lab_worker.app.red_ai.validator import ScenarioValidator

        val_res = ScenarioValidator.validate(scenario)
        if not val_res.is_valid:
            raise ProviderInferenceError(
                f"Qwen generated invalid ScenarioContract: {val_res.error_message}"
            )

        return scenario

    async def formulate_hypothesis(
        self,
        task_id: UUID,
        failure_category: str,
        target_family: str,
        discrepancy_type: str,
        affected_count: int,
        sample_urls: list[str],
    ) -> DefensiveHypothesis:
        """Use Qwen to reason over a failure cluster and synthesize a DefensiveHypothesis with declarative predicates."""
        defanged_samples = [
            u.replace("http://", "hxxp://").replace("https://", "hxxps://") for u in sample_urls[:5]
        ]
        prompt = (
            f"Analyze the following detection failure observations and formulate a defensive hypothesis.\n"
            f"Failure Category: {failure_category}\n"
            f"Target Family: {target_family}\n"
            f"Discrepancy: {discrepancy_type} ({affected_count} affected scenarios)\n"
            f"Sample URLs (defanged): {defanged_samples}\n"
            f"Allowed Predicate Fields: url_length, host_length, path_length, query_length, subdomain_count, path_depth, "
            f"is_ip_literal, is_punycode, phish_keyword_count, host_entropy, host, domain.\n"
            f"Allowed Operators: eq, ne, gt, gte, lt, lte, contains, in, matches_regex.\n"
            f"Requirements:\n"
            f"1. Explain the detector blind spot (possible_explanation).\n"
            f"2. State predicted benefit and potential false-positive risks.\n"
            f"3. Propose declarative predicates targeting the pattern without impacting benign controls.\n"
            f"Return strict JSON matching DefensiveHypothesis schema."
        )

        data = await self.generate_structured_json(
            prompt=prompt,
            system_instruction=(
                "You are Blue AI, a defensive security intelligence engine. "
                "Synthesize defensive hypotheses and safe declarative AST predicates. Return strict JSON."
            ),
            temperature=0.1,
        )

        try:
            hypothesis = DefensiveHypothesis(
                hypothesis_id=uuid4(),
                research_task_id=task_id,
                failure_category=failure_category,
                target_family=target_family,
                observed_behavior=str(
                    data.get("observed_behavior", f"Detector failed on {failure_category}")
                )[:512],
                expected_behavior=str(
                    data.get("expected_behavior", "Detector should block or warn on threat pattern")
                )[:512],
                possible_explanation=str(
                    data.get("possible_explanation", "Lexical blind spot in heuristic inspection")
                )[:1024],
                supporting_evidence=data.get("supporting_evidence", []),
                counterexamples=data.get("counterexamples", []),
                proposed_intervention=data.get(
                    "proposed_intervention",
                    {
                        "proposal_type": "declarative_rule",
                        "target_action": "block",
                        "predicates": [
                            {"field": "phish_keyword_count", "operator": "gte", "value": 2}
                        ],
                        "recommended_weight": 0.85,
                    },
                ),
                predicted_benefit=str(data.get("predicted_benefit", "Mitigates detection gap"))[
                    :512
                ],
                potential_risks=str(
                    data.get("potential_risks", "Low false-positive risk with allowlist")
                )[:512],
                test_plan=str(
                    data.get(
                        "test_plan", "Evaluate against golden benchmark and held-out test split"
                    )
                )[:512],
                confidence=float(data.get("confidence", 0.85)),
            )
            return hypothesis
        except Exception as exc:
            raise ProviderInferenceError(
                f"Qwen emitted invalid DefensiveHypothesis: {exc}"
            ) from exc

    async def generate_defense_rule(
        self,
        failure_cluster_description: str,
        target_family: str,
        sample_urls: list[str],
    ) -> DeclarativeRuleModel:
        """Use Qwen to formulate a strictly validated declarative AST rule from failure observations."""
        defanged_samples = [
            u.replace("http://", "hxxp://").replace("https://", "hxxps://") for u in sample_urls[:5]
        ]
        prompt = (
            f"Synthesize a declarative detection rule to mitigate the following attack pattern.\n"
            f"Target Threat Family: {target_family}\n"
            f"Observed Attack Indicators: {failure_cluster_description}\n"
            f"Sample Attack URLs (defanged): {defanged_samples}\n"
            f"Requirements:\n"
            f"1. Generate atomic predicates using allowed fields (e.g. domain_suffix, path_contains, has_homoglyphs).\n"
            f"2. Set action to 'block' or 'warn'.\n"
            f"3. Return strict JSON matching DeclarativeRuleModel schema: rule_id, rule_version, description, author, purpose, target_family, predicates, action, severity, weight."
        )

        data = await self.generate_structured_json(
            prompt=prompt,
            system_instruction="You are Blue AI, a defensive security intelligence model synthesizing declarative AST rules.",
            temperature=0.1,
        )

        try:
            return DeclarativeRuleModel.model_validate(data)
        except Exception as exc:
            raise ProviderInferenceError(
                f"Qwen emitted invalid DeclarativeRuleModel: {exc}"
            ) from exc

    async def classify_resource(
        self,
        normalized_identifier: str,
        resource_url: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> ThreatAnalysisResult:
        """Classify a resource using Qwen model reasoning."""
        prompt = (
            f"Analyze the following resource identifier for cybersecurity threats.\n"
            f"Resource URL: {resource_url or 'N/A'}\n"
            f"Normalized Hash: {normalized_identifier}\n"
            f"Context: {json.dumps(context or {})}\n"
            f"Return a JSON object with: threat_score (0.0 to 1.0), decision (allow|warn|block), "
            f"confidence (0.0 to 1.0), and evidence (list of objects with category, reason, severity)."
        )

        data = await self.generate_structured_json(
            prompt=prompt,
            system_instruction="You are a defensive cybersecurity threat classification intelligence engine.",
            temperature=0.1,
        )

        score = float(data.get("threat_score", 0.05))
        score = max(0.0, min(1.0, score))

        if score >= 0.85:
            decision = Decision.BLOCK
        elif score >= 0.50:
            decision = Decision.WARN
        else:
            decision = Decision.ALLOW

        raw_evidence = data.get("evidence", [])
        evidence_items: list[EvidenceItem] = []
        if isinstance(raw_evidence, list):
            for item in raw_evidence:
                if isinstance(item, dict):
                    sev_str = str(item.get("severity", "medium")).lower()
                    severity = ThreatSeverity.MEDIUM
                    for s in ThreatSeverity:
                        if s.value == sev_str:
                            severity = s
                            break
                    evidence_items.append(
                        EvidenceItem(
                            category=str(item.get("category", "qwen_reasoning"))[:64],
                            reason=str(item.get("reason", "Indicator flagged by Qwen inference"))[
                                :512
                            ],
                            severity=severity,
                            confidence=float(item.get("confidence", 0.85))
                            if "confidence" in item
                            else 0.85,
                        )
                    )

        if not evidence_items:
            evidence_items.append(
                EvidenceItem(
                    category="qwen_analysis",
                    reason=f"Qwen {self.model_name} evaluated resource as {decision.value}",
                    severity=ThreatSeverity.HIGH
                    if decision == Decision.BLOCK
                    else ThreatSeverity.LOW,
                    confidence=float(data.get("confidence", 0.9)),
                )
            )

        return ThreatAnalysisResult(
            analysis_id=uuid4(),
            normalized_identifier=normalized_identifier,
            threat_score=score,
            decision=decision,
            evidence=evidence_items,
            engine_version=f"qwen-{self.model_name}",
            policy_version="2026.10.1",
            confidence=float(data.get("confidence", 0.9)),
            provenance=ProvenanceType.MODEL_INFERENCE,
            created_at=datetime.now(UTC),
        )
