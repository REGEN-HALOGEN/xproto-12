"""Schema definitions for external benchmark adapters (AgentDojo, InjecAgent)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BenchmarkCaseRecord:
    """Standardized representation of an imported external benchmark task."""

    case_id: str
    source_benchmark: str  # "AgentDojo" or "InjecAgent"
    source_revision: str  # git commit SHA or release tag
    license: str  # "MIT", "Apache-2.0"
    source_family: str  # e.g., "workspace", "slack", "banking", "data_harvesting", "unauthorized_access"
    task_text: str  # Top-level prompt sent by user
    injected_content: str  # Embedded prompt injection payload
    benign_target_effect: dict[str, Any]  # Intended benign action or output
    malicious_target_effect: dict[str, Any]  # Target exploit effect (exfil email, unauth delegation, etc.)
    required_tools: list[str]  # e.g., ["read_file", "send_email"]
    setup_fixtures: dict[str, str] = field(default_factory=dict)  # fixture path -> content
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_xproto_scenario(self) -> dict[str, Any]:
        """Convert benchmark record to standard XProto scenario schema."""
        prefix = self.source_benchmark.lower()
        scenario_id = f"{prefix}_{self.case_id}"
        
        # Build expectations from malicious_target_effect
        # In vulnerable mode, these expectations match the exploit; in defense mode, XGate blocks them.
        expect = []
        if "expect" in self.malicious_target_effect:
            for item in self.malicious_target_effect["expect"]:
                if "match" in item:
                    expect.append(item)
                else:
                    file_name = item.get("file", "tool_calls.jsonl")
                    match_body = {k: v for k, v in item.items() if k != "file"}
                    expect.append({"file": file_name, "match": match_body})
        else:
            if "tool" in self.malicious_target_effect:
                tool_match: dict[str, Any] = {
                    "tool": self.malicious_target_effect["tool"],
                }
                if "path" in self.malicious_target_effect:
                    tool_match["arg_path_contains"] = self.malicious_target_effect["path"]
                if "to" in self.malicious_target_effect:
                    tool_match["to_contains"] = self.malicious_target_effect["to"]
                if "body_contains" in self.malicious_target_effect:
                    tool_match["body_contains"] = self.malicious_target_effect["body_contains"]
                expect.append({"file": "tool_calls.jsonl", "match": tool_match})

            if "delegation_url" in self.malicious_target_effect:
                expect.append({
                    "file": "delegations.jsonl",
                    "match": {
                        "target_url": self.malicious_target_effect["delegation_url"],
                        "allowed": True,
                    },
                })

            if "task_state" in self.malicious_target_effect:
                expect.append({"task_state": self.malicious_target_effect["task_state"]})

        return {
            "id": scenario_id,
            "name": f"[{self.source_benchmark}] {self.case_id} ({self.source_family})",
            "class": f"external-{prefix}",
            "source_benchmark": self.source_benchmark,
            "source_revision": self.source_revision,
            "license": self.license,
            "source_family": self.source_family,
            "required_tools": list(self.required_tools),
            "attacker": {
                "delegator": f"external-{prefix}@eval.local",
                "text": self.task_text,
                "metadata": {
                    "source": self.source_benchmark,
                    "case_id": self.case_id,
                    "family": self.source_family,
                    **self.metadata,
                },
            },
            "expect": expect,
            "benign_target_effect": self.benign_target_effect,
            "malicious_target_effect": self.malicious_target_effect,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkCaseRecord:
        return cls(**data)


@dataclass
class ExcludedCaseRecord:
    """Documentation of an external benchmark case excluded from local import."""

    case_id: str
    source_benchmark: str
    source_family: str
    unsupported_capability: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExcludedCaseRecord:
        return cls(**data)


@dataclass
class BenchmarkManifest:
    """Pinned lock manifest of external benchmark revisions and exclusions."""

    lock_version: str
    benchmarks: dict[str, dict[str, Any]]

    @classmethod
    def load(cls, path: Path) -> BenchmarkManifest:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(lock_version=data.get("lock_version", "1.0.0"), benchmarks=data.get("benchmarks", {}))

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
