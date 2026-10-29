"""Log content is ATTACKER-CONTROLLED (command lines, script blocks, file names).  Before it reaches an LLM it is
(1) stripped of control characters, (2) length-capped, (3) angle-bracket-escaped so it cannot close our data fence,
(4) scanned for instruction-like text.  Flags are reported to the analyst and counted in the experiments (RQ4)."""
from __future__ import annotations

import re

INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts?)", r"disregard (the )?(system|previous|above)",
    r"you are (now |actually )?(a|an|the) ", r"system prompt", r"\bnew instructions?\b", r"(?m)^\s*(assistant|system|developer)\s*:",
    r"do not (report|flag|mention|escalate)", r"mark (this )?(as )?(a )?(false positive|benign|safe)", r"close_false_positive",
    r"approve (this|the) action", r"</?untrusted", r"\boutput (only )?the following\b", r"respond with", r"canary-\w+",
]
_RX = [re.compile(p, re.I) for p in INJECTION_PATTERNS]
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(text: str, max_len: int = 300) -> str:
    t = _CTRL.sub("", str(text))
    t = t.replace("<", "\u2039").replace(">", "\u203a")          # single angle quotes: visible, but cannot form tags
    return t if len(t) <= max_len else t[:max_len] + f"...[+{len(t) - max_len} chars truncated]"


def injection_flags(text: str) -> list[str]:
    return [rx.pattern for rx in _RX if rx.search(str(text))]


def wrap(text: str, max_len: int = 300) -> tuple[str, list[str]]:
    """Return (safe text, flags)."""
    return clean(text, max_len), injection_flags(text)
