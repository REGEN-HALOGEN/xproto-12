"""Deterministic regex-based planner control baseline for XProto-12."""

from __future__ import annotations

import re
import time
from typing import Any

from xproto.planners.base import (
    DelegateDecision,
    PlanDecision,
    PlanRequest,
    PlanResult,
    Planner,
    RefuseDecision,
    RespondDecision,
    ToolCallDecision,
)

EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
PATH_RE = re.compile(r"(/[\w./~\-]+|~[/\w.\-]+|testdata/[\w./\-]+)")
DELEGATE_RE = re.compile(r"delegate to (https?://[^\s:]+(?::\d+)?)\s*:?\s*(.*)", re.I)
CAPABILITY_RE = re.compile(r"use the ([\w\- ]+?) (?:relay|agent)\s*(?:to\s*|:\s*)?(.*)", re.I)
INSTRUCTION_RE = re.compile(r"^INSTRUCTION:\s*(.+)$", re.M)


class RegexPlanner(Planner):
    """Deterministic regex rule-based planner preserved as an experimental control baseline."""

    def __init__(self, model_digest: str = "regex-control-v1"):
        self.model_digest = model_digest

    async def plan(self, request: PlanRequest) -> PlanResult:
        t0 = time.perf_counter()
        t = request.task_text.strip()
        decision: PlanDecision

        # Unwrap structured or tagged injection prefixes if present
        inst_m = re.search(r"(?:INSTRUCTION|INSTRUCCIÓN|ANWEISUNG|DIRECTIVE)[\s:]+(.+?)(?:\"|\}|$|\n)", t, re.I)
        if inst_m:
            t = inst_m.group(1).strip()

        m = DELEGATE_RE.search(t)
        if m:
            target_url = m.group(1)
            task_text = m.group(2) or t
            cap = ""
            for word in ["admin-control", "file-audit", "audit", "file-ops", "summarize"]:
                if word in t.lower():
                    cap = "file-audit" if word == "audit" else word
                    break
            decision = DelegateDecision(target=target_url, task_text=task_text, capability=cap)
            duration_ms = (time.perf_counter() - t0) * 1000
            return PlanResult(
                decision=decision,
                raw_response=f"DELEGATE {target_url} {task_text}",
                model_digest=self.model_digest,
                sampling_config={"mode": "deterministic"},
                duration_ms=duration_ms,
            )

        # 2. Capability-based delegation
        m = CAPABILITY_RE.search(t)
        if m:
            cap = m.group(1).strip().lower().replace(" ", "-")
            subtask = m.group(2).strip() or t
            target_url = None
            for dt in request.delegation_targets:
                if dt.capability == cap:
                    target_url = dt.url
                    break
            if target_url:
                decision = DelegateDecision(
                    target=target_url, task_text=subtask, capability=cap
                )
            else:
                decision = RefuseDecision(reason=f"no known agent with capability '{cap}'")
            duration_ms = (time.perf_counter() - t0) * 1000
            return PlanResult(
                decision=decision,
                raw_response=f"CAPABILITY {cap} -> {target_url}",
                model_digest=self.model_digest,
                sampling_config={"mode": "deterministic"},
                duration_ms=duration_ms,
            )

        # 3. Email sending (with potential read_file prerequisite)
        email = EMAIL_RE.search(t)
        if email and ("email" in t.lower() or "e-mail" in t.lower()):
            addr = email.group(0)
            pm = (
                re.search(r"(?:contents|summary|contenido|inhalt)\s+(?:of|de|von)\s+(\S+)", t, re.I)
                or PATH_RE.search(t)
            )
            if pm:
                file_path = pm.group(1)
                # Check if history already contains the read_file tool result
                read_content = None
                for seg in reversed(request.history):
                    if seg.provenance == "mcp_tool_result" and seg.metadata.get("tool") == "read_file":
                        read_content = seg.text
                        break
                if read_content is not None:
                    decision = ToolCallDecision(
                        tool="send_email",
                        args={"to": addr, "subject": "requested contents", "body": read_content},
                    )
                else:
                    decision = ToolCallDecision(tool="read_file", args={"path": file_path})
            else:
                decision = ToolCallDecision(
                    tool="send_email",
                    args={"to": addr, "subject": "message", "body": t},
                )
            duration_ms = (time.perf_counter() - t0) * 1000
            return PlanResult(
                decision=decision,
                raw_response=f"EMAIL {decision.to_dict()}",
                model_digest=self.model_digest,
                sampling_config={"mode": "deterministic"},
                duration_ms=duration_ms,
            )

        # 4. Web search
        if re.search(r"search (the )?web for|search for", t, re.I):
            q = re.split(r"search (the )?web for|search for", t, flags=re.I)[-1].strip(" :")
            decision = ToolCallDecision(tool="search_web", args={"query": q or t})
            duration_ms = (time.perf_counter() - t0) * 1000
            return PlanResult(
                decision=decision,
                raw_response=f"SEARCH {q or t}",
                model_digest=self.model_digest,
                sampling_config={"mode": "deterministic"},
                duration_ms=duration_ms,
            )

        # 5. List directory
        if ("director" in t.lower() and ("list" in t.lower() or "show" in t.lower() or "audit" in t.lower())) or "audit" in t.lower() and "public" in t.lower():
            pm = PATH_RE.search(t)
            path = pm.group(1) if pm else "testdata"
            decision = ToolCallDecision(tool="list_directory", args={"path": path})
            duration_ms = (time.perf_counter() - t0) * 1000
            return PlanResult(
                decision=decision,
                raw_response=f"LIST {path}",
                model_digest=self.model_digest,
                sampling_config={"mode": "deterministic"},
                duration_ms=duration_ms,
            )

        # 6. Read / summarize file
        pm = PATH_RE.search(t)
        if pm and re.search(r"\b(read|open|summar)", t, re.I):
            path = pm.group(1)
            decision = ToolCallDecision(tool="read_file", args={"path": path})
            duration_ms = (time.perf_counter() - t0) * 1000
            return PlanResult(
                decision=decision,
                raw_response=f"READ {path}",
                model_digest=self.model_digest,
                sampling_config={"mode": "deterministic"},
                duration_ms=duration_ms,
            )

        # Fallback response if no regex matched
        decision = RespondDecision(
            content=(
                "I could not map that request to a tool. "
                "Try: 'summarize file <path>', 'email the contents of <path> to <addr>', "
                "'list directory <path>', 'search the web for <query>'."
            )
        )
        duration_ms = (time.perf_counter() - t0) * 1000
        return PlanResult(
            decision=decision,
            raw_response="NO_MATCH",
            model_digest=self.model_digest,
            sampling_config={"mode": "deterministic"},
            duration_ms=duration_ms,
        )
