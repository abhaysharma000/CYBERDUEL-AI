"""Scenario Mutation Engine for safe, controlled variation of synthetic threat scenarios.

CRITICAL SAFETY BOUNDARY:
Mutations operate strictly on synthetic URL strings without issuing network requests.
Every mutation explicitly audits lineage, records semantic preservation status,
and marks uncertain ground-truth when transformations alter threat semantics.
"""

from __future__ import annotations

import random
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from uuid import uuid4

from cyberduel_contracts.enums import Decision, ExpectedClass
from cyberduel_contracts.lab import ScenarioContract, TransformationRecord


class ScenarioMutationEngine:
    """Engine applying deterministic, bounded mutations to synthetic scenario fixtures."""

    MAX_MUTATION_DEPTH = 5

    OPERATORS = [
        "case_variation",
        "query_param_injection",
        "path_depth_variation",
        "subdomain_prefix",
        "port_explicit_injection",
        "punycode_unicode_swap",
        "param_reorder",
    ]

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self._rng = random.Random(seed)

    def mutate(
        self,
        scenario: ScenarioContract,
        operator: str | None = None,
        max_depth: int = MAX_MUTATION_DEPTH,
    ) -> ScenarioContract:
        """Apply a single controlled mutation operator to the input scenario."""
        current_depth = len(scenario.transformation_history)
        if current_depth >= max_depth:
            # Cannot mutate beyond max depth ceiling
            return scenario

        if operator is None:
            operator = self._rng.choice(self.OPERATORS)

        raw_url = str(scenario.input_fixture.get("raw_url", ""))
        parsed = urlparse(raw_url)

        new_url = raw_url
        preserved_semantics = True
        relabel_required = False
        new_class = scenario.expected_class
        new_decision = scenario.expected_decision
        params: dict[str, Any] = {"operator": operator}

        if operator == "case_variation":
            # Semantics preserved: Hostnames are case-insensitive in DNS/HTTP
            netloc = parsed.netloc
            # Alternate casing of host
            mutated_netloc = "".join(
                c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(netloc)
            )
            new_url = urlunparse(parsed._replace(netloc=mutated_netloc))
            params["original_netloc"] = netloc
            params["mutated_netloc"] = mutated_netloc

        elif operator == "query_param_injection":
            # Harmless query injection: adds non-critical diagnostic parameter
            qs = parse_qs(parsed.query)
            tag_val = f"lab_mut_{self._rng.randint(100, 999)}"
            qs["_lab_diag"] = [tag_val]
            new_query = urlencode(qs, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            params["injected_param"] = "_lab_diag"
            params["injected_value"] = tag_val

        elif operator == "path_depth_variation":
            # Modifies path: may alter semantic classification if path contained credential theft token
            path_segments = [p for p in parsed.path.split("/") if p]
            if len(path_segments) > 1 and self._rng.random() > 0.5:
                # Truncate one segment
                removed = path_segments.pop()
                params["action"] = "truncate_segment"
                params["removed_segment"] = removed
                # If removed segment was a known phishing keyword, semantics may have changed
                if any(kw in removed.lower() for kw in ["login", "verify", "password", "secure"]):
                    preserved_semantics = False
                    relabel_required = True
                    new_class = ExpectedClass.UNCERTAIN.value
                    new_decision = Decision.WARN
            else:
                # Append benign sub-path
                added = f"substep_{self._rng.randint(1, 9)}"
                path_segments.append(added)
                params["action"] = "append_segment"
                params["added_segment"] = added

            new_path = "/" + "/".join(path_segments)
            new_url = urlunparse(parsed._replace(path=new_path))

        elif operator == "subdomain_prefix":
            # Adds benign staging/test prefix
            netloc = parsed.netloc
            prefix = self._rng.choice(["stage", "qa", "preview", "node-1"])
            # Ensure not already prefixed
            if not netloc.startswith(f"{prefix}."):
                new_netloc = f"{prefix}.{netloc}"
                new_url = urlunparse(parsed._replace(netloc=new_netloc))
                params["prefix_added"] = prefix

        elif operator == "port_explicit_injection":
            # Explicitly injects default port 80 or 443, or non-standard port
            netloc = parsed.netloc
            if ":" not in netloc:
                if self._rng.random() > 0.5:
                    # Injects standard port (semantics preserved, normalizer will strip it)
                    port = 443 if parsed.scheme == "https" else 80
                    new_netloc = f"{netloc}:{port}"
                    params["port_type"] = "default"
                else:
                    # Injects non-standard port (semantics altered: introduces network anomaly)
                    port = self._rng.choice([8080, 8443, 8888])
                    new_netloc = f"{netloc}:{port}"
                    params["port_type"] = "non_standard"
                    params["port"] = port
                    if scenario.expected_class == ExpectedClass.BENIGN:
                        # Non-standard port elevates benign baseline to at least suspicious/warn
                        preserved_semantics = False
                        relabel_required = True
                        new_class = ExpectedClass.SUSPICIOUS.value
                        new_decision = Decision.WARN

                new_url = urlunparse(parsed._replace(netloc=new_netloc))

        elif operator == "punycode_unicode_swap":
            # Swap between punycode and decoded representation
            netloc = parsed.netloc
            if "xn--" in netloc:
                try:
                    decoded = netloc.encode("ascii").decode("idna")
                    new_url = urlunparse(parsed._replace(netloc=decoded))
                    params["direction"] = "punycode_to_unicode"
                    params["unicode"] = decoded
                except Exception:
                    new_url = raw_url
            else:
                try:
                    encoded = netloc.encode("idna").decode("ascii")
                    if encoded != netloc:
                        new_url = urlunparse(parsed._replace(netloc=encoded))
                        params["direction"] = "unicode_to_punycode"
                        params["punycode"] = encoded
                except Exception:
                    new_url = raw_url

        elif operator == "param_reorder":
            # Reorders query string parameters (semantics strictly preserved)
            qs = parse_qs(parsed.query)
            if len(qs) > 1:
                items = list(qs.items())
                self._rng.shuffle(items)
                new_query = urlencode(dict(items), doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                params["reordered"] = True

        # Construct transformation record
        tx_record = TransformationRecord(
            operator=operator,
            parameters=params,
            preserved_semantics=preserved_semantics,
            relabel_required=relabel_required,
        )

        history = list(scenario.transformation_history)
        history.append(tx_record.model_dump(mode="json"))

        new_fixture = dict(scenario.input_fixture)
        new_fixture["raw_url"] = new_url

        base_name = scenario.scenario_name.split(" (Mutated:")[0]
        mutated_name = f"{base_name} (Mutated: {operator})"[:128]
        desc = f"Mutated variation of {base_name} using {operator}"[:512]

        return ScenarioContract(
            scenario_id=uuid4(),
            schema_version=scenario.schema_version,
            scenario_family=scenario.scenario_family,
            scenario_name=mutated_name,
            description=desc,
            expected_class=new_class,
            expected_decision=new_decision,
            difficulty=scenario.difficulty,
            tags=list(set(scenario.tags + [f"mutated:{operator}"])),
            seed=self.seed,
            generator_version=scenario.generator_version,
            mutation_parent_id=scenario.scenario_id,
            transformation_history=history,
            input_fixture=new_fixture,
            expected_evidence=list(scenario.expected_evidence),
            provenance={
                "parent_id": str(scenario.scenario_id),
                "mutation_operator": operator,
                "preserved_semantics": preserved_semantics,
                "relabel_required": relabel_required,
                "generator_version": scenario.generator_version,
            },
            safety_classification="harmless_synthetic",
        )
