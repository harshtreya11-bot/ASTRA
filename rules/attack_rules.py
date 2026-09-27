"""
rules/attack_rules.py - All regex-based detection rules
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------

@dataclass
class AttackRule:
    rule_id: str
    attack_type: str
    description: str
    severity: str                    # CRITICAL | HIGH | MEDIUM | LOW
    base_confidence: int             # 0-100
    patterns: List[re.Pattern]
    enabled: bool = True
    require_multiple: bool = False   # need >1 pattern match for full confidence
    false_positive_guards: List[re.Pattern] = field(default_factory=list)
    recommended_action: str = ""

    def matches(self, text: str) -> tuple[bool, int, str]:
        """
        Returns (matched, confidence, evidence_snippet).
        """
        if not self.enabled:
            return False, 0, ""

        hits = []
        for pat in self.patterns:
            m = pat.search(text)
            if m:
                hits.append(m.group(0)[:120])

        if not hits:
            return False, 0, ""

        # Check false-positive guards
        for guard in self.false_positive_guards:
            if guard.search(text):
                return False, 0, ""

        # Confidence adjustment
        confidence = self.base_confidence
        if self.require_multiple:
            if len(hits) < 2:
                confidence = int(confidence * 0.55)
            else:
                confidence = min(100, int(confidence * 1.1))

        evidence = " | ".join(hits[:3])
        return True, confidence, evidence


# ---------------------------------------------------------------------------
# Helper to compile patterns (case-insensitive)
# ---------------------------------------------------------------------------

def _p(*patterns: str) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


# ---------------------------------------------------------------------------
# SQL INJECTION RULES
# ---------------------------------------------------------------------------

SQLI_RULES: List[AttackRule] = [
    AttackRule(
        rule_id="SQLI-001",
        attack_type="SQL Injection",
        description="Boolean-based authentication bypass (OR 1=1 variants)",
        severity="CRITICAL",
        base_confidence=92,
        patterns=_p(
            r"['\"]?\s*or\s+['\"]?1['\"]?\s*=\s*['\"]?1",
            r"['\"]?\s*or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
            r"' or '",
            r"\" or \"",
            r"\bor\b\s+\btrue\b",
        ),
        recommended_action=(
            "1. Review server logs for successful authentication.\n"
            "2. Check if input is properly parameterized.\n"
            "3. Inspect related requests from this IP."
        ),
    ),
    AttackRule(
        rule_id="SQLI-002",
        attack_type="SQL Injection",
        description="UNION-based SQL injection (data extraction)",
        severity="CRITICAL",
        base_confidence=90,
        patterns=_p(
            r"\bunion\b\s+(all\s+)?\bselect\b",
            r"\bunion\b.*?\bselect\b.*?\bfrom\b",
        ),
        recommended_action=(
            "1. Check if attacker retrieved sensitive data.\n"
            "2. Review database query logs.\n"
            "3. Implement parameterized queries immediately."
        ),
    ),
    AttackRule(
        rule_id="SQLI-003",
        attack_type="SQL Injection",
        description="Time-based blind SQL injection (SLEEP/BENCHMARK/WAITFOR)",
        severity="CRITICAL",
        base_confidence=88,
        patterns=_p(
            r"\bsleep\s*\(\s*\d+",
            r"\bbenchmark\s*\(\s*\d+",
            r"\bwaitfor\s+delay\b",
            r"\bpg_sleep\s*\(",
        ),
        recommended_action=(
            "1. Check application response times.\n"
            "2. Confirm blind injection was executed.\n"
            "3. Parameterize all queries."
        ),
    ),
    AttackRule(
        rule_id="SQLI-004",
        attack_type="SQL Injection",
        description="SQL DDL/DML statements (DROP/INSERT/DELETE/UPDATE)",
        severity="CRITICAL",
        base_confidence=85,
        patterns=_p(
            r"\bdrop\s+table\b",
            r"\bdrop\s+database\b",
            r"\binsert\s+into\b",
            r"\bdelete\s+from\b",
            r"\bupdate\s+\w+\s+set\b",
            r"\btruncate\s+table\b",
        ),
        recommended_action=(
            "1. Verify database integrity.\n"
            "2. Check transaction logs.\n"
            "3. Apply principle of least privilege to DB user."
        ),
    ),
    AttackRule(
        rule_id="SQLI-005",
        attack_type="SQL Injection",
        description="Information schema / metadata extraction",
        severity="HIGH",
        base_confidence=82,
        patterns=_p(
            r"\binformation_schema\b",
            r"\bsys\.tables\b",
            r"\bsysobjects\b",
            r"\bpg_tables\b",
            r"\bpg_catalog\b",
        ),
        recommended_action=(
            "1. Attacker may be mapping database structure.\n"
            "2. Restrict information_schema access.\n"
            "3. Review parameterized query implementation."
        ),
    ),
    AttackRule(
        rule_id="SQLI-006",
        attack_type="SQL Injection",
        description="SQL command execution (xp_cmdshell / stacked queries)",
        severity="CRITICAL",
        base_confidence=95,
        patterns=_p(
            r"\bxp_cmdshell\b",
            r";\s*exec\s+",
            r";\s*execute\s+",
            r"\bexec\s*\(\s*@",
        ),
        recommended_action=(
            "1. IMMEDIATE: Check if OS commands were executed via DB.\n"
            "2. Review SQL Server error logs.\n"
            "3. Disable xp_cmdshell immediately."
        ),
    ),
    AttackRule(
        rule_id="SQLI-007",
        attack_type="SQL Injection",
        description="SQL comment-based injection",
        severity="HIGH",
        base_confidence=70,
        patterns=_p(
            r"--\s+",
            r"#\s+\w",
            r"/\*.*?\*/",
            r";\s*--",
        ),
        false_positive_guards=_p(r"^https?://"),
        recommended_action=(
            "1. Verify the comment sequence appears in a query parameter.\n"
            "2. Cross-reference with other SQL patterns from this IP."
        ),
    ),
]

# ---------------------------------------------------------------------------
# XSS RULES
# ---------------------------------------------------------------------------

XSS_RULES: List[AttackRule] = [
    AttackRule(
        rule_id="XSS-001",
        attack_type="Cross-Site Scripting",
        description="Script tag injection",
        severity="HIGH",
        base_confidence=94,
        patterns=_p(
            r"<script[^>]*>",
            r"</script>",
            r"%3cscript",
            r"%3c/script",
        ),
        recommended_action=(
            "1. Check if the payload was stored or reflected.\n"
            "2. Implement Content Security Policy.\n"
            "3. Encode output before rendering."
        ),
    ),
    AttackRule(
        rule_id="XSS-002",
        attack_type="Cross-Site Scripting",
        description="JavaScript protocol injection",
        severity="HIGH",
        base_confidence=90,
        patterns=_p(
            r"javascript\s*:",
            r"vbscript\s*:",
            r"data\s*:\s*text/html",
        ),
        recommended_action=(
            "1. Sanitize href/src attributes.\n"
            "2. Block javascript: protocol in user input."
        ),
    ),
    AttackRule(
        rule_id="XSS-003",
        attack_type="Cross-Site Scripting",
        description="Event handler injection (onXXX= attributes)",
        severity="HIGH",
        base_confidence=88,
        patterns=_p(
            r"\bon\w+\s*=",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
        ),
        recommended_action=(
            "1. Strip or encode HTML event attributes.\n"
            "2. Implement strict HTML sanitization."
        ),
    ),
    AttackRule(
        rule_id="XSS-004",
        attack_type="Cross-Site Scripting",
        description="DOM manipulation via JS functions",
        severity="HIGH",
        base_confidence=85,
        patterns=_p(
            r"\balert\s*\(",
            r"\bprompt\s*\(",
            r"\bconfirm\s*\(",
            r"\bdocument\.cookie\b",
            r"\bdocument\.write\b",
            r"\bwindow\.location\b",
            r"\beval\s*\(",
        ),
        recommended_action=(
            "1. Verify if payload is reflected back to users.\n"
            "2. Implement output encoding."
        ),
    ),
    AttackRule(
        rule_id="XSS-005",
        attack_type="Cross-Site Scripting",
        description="Iframe injection",
        severity="MEDIUM",
        base_confidence=80,
        patterns=_p(
            r"<iframe[^>]*>",
            r"%3ciframe",
        ),
        recommended_action=(
            "1. Block HTML tag injection.\n"
            "2. Set X-Frame-Options header."
        ),
    ),
]

# ---------------------------------------------------------------------------
# PATH TRAVERSAL RULES
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_RULES: List[AttackRule] = [
    AttackRule(
        rule_id="PATH-001",
        attack_type="Path Traversal",
        description="Directory traversal sequences (../)",
        severity="HIGH",
        base_confidence=88,
        patterns=_p(
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e[%2f/\\]",
            r"%2e%2e%2f",
            r"\.\.%2f",
            r"\.\.%5c",
            r"%252e%252e",
        ),
        recommended_action=(
            "1. Verify if sensitive files were accessed.\n"
            "2. Implement path canonicalization and sandboxing.\n"
            "3. Check application file-serving logic."
        ),
    ),
    AttackRule(
        rule_id="PATH-002",
        attack_type="Path Traversal",
        description="Sensitive file access attempt (Linux)",
        severity="CRITICAL",
        base_confidence=92,
        patterns=_p(
            r"/etc/passwd",
            r"/etc/shadow",
            r"/etc/hosts",
            r"/proc/self",
            r"/var/log/",
            r"~/.ssh/",
            r"/root/",
        ),
        recommended_action=(
            "1. IMMEDIATE: Check if file contents were returned in response.\n"
            "2. Restrict file-serving to permitted directories.\n"
            "3. Review 200 responses to this request."
        ),
    ),
    AttackRule(
        rule_id="PATH-003",
        attack_type="Path Traversal",
        description="Sensitive file access attempt (Windows)",
        severity="CRITICAL",
        base_confidence=90,
        patterns=_p(
            r"boot\.ini",
            r"win\.ini",
            r"system\.ini",
            r"windows[/\\]system32",
            r"winnt[/\\]system32",
            r"cmd\.exe",
        ),
        recommended_action=(
            "1. Review if Windows system files were served.\n"
            "2. Implement strict path validation."
        ),
    ),
]

# ---------------------------------------------------------------------------
# COMMAND INJECTION RULES
# ---------------------------------------------------------------------------

CMDI_RULES: List[AttackRule] = [
    AttackRule(
        rule_id="CMDI-001",
        attack_type="Command Injection",
        description="Shell separator + command pattern (;cmd, &&cmd, |cmd)",
        severity="CRITICAL",
        base_confidence=90,
        patterns=_p(
            r";\s*(whoami|id|ls|cat|pwd|uname|ifconfig|ipconfig|net\s+user|dir)",
            r"\|\s*(whoami|id|ls|cat|pwd|uname|ifconfig)",
            r"&&\s*(whoami|id|ls|cat|pwd)",
            r"\$\((whoami|id|ls|cat|pwd)\)",
            r"`(whoami|id|ls|cat|pwd)`",
        ),
        recommended_action=(
            "1. IMMEDIATE: Check server process logs for command execution.\n"
            "2. Validate and sanitize all input passed to OS commands.\n"
            "3. Never pass user input to shell without strict allow-listing."
        ),
    ),
    AttackRule(
        rule_id="CMDI-002",
        attack_type="Command Injection",
        description="Shell binary access (/bin/sh, /bin/bash, cmd.exe)",
        severity="CRITICAL",
        base_confidence=88,
        patterns=_p(
            r"/bin/(sh|bash|dash|zsh|csh)",
            r"cmd\.exe",
            r"powershell",
            r"/usr/bin/(python|perl|ruby|nc|ncat|netcat|wget|curl)\b",
        ),
        recommended_action=(
            "1. Check if shell was spawned.\n"
            "2. Restrict execution of system binaries from web process."
        ),
    ),
    AttackRule(
        rule_id="CMDI-003",
        attack_type="Command Injection",
        description="Network tool abuse (wget/curl/nc in parameters)",
        severity="HIGH",
        base_confidence=75,
        patterns=_p(
            r"\bwget\s+https?://",
            r"\bcurl\s+https?://",
            r"\bnc\s+-",
            r"\bnetcat\b",
        ),
        false_positive_guards=_p(r"^(https?://(docs|www|api)\.)",),
        recommended_action=(
            "1. Check if attacker exfiltrated data or downloaded malware.\n"
            "2. Monitor outbound network connections from web server."
        ),
    ),
]

# ---------------------------------------------------------------------------
# PARAMETER MANIPULATION RULES
# ---------------------------------------------------------------------------

PARAM_RULES: List[AttackRule] = [
    AttackRule(
        rule_id="PARAM-001",
        attack_type="Parameter Manipulation",
        description="Null byte injection",
        severity="MEDIUM",
        base_confidence=78,
        patterns=_p(
            r"%00",
            r"\x00",
            r"\\x00",
            r"\\0",
        ),
        recommended_action=(
            "1. Strip null bytes from all user input.\n"
            "2. Validate input types strictly."
        ),
    ),
    AttackRule(
        rule_id="PARAM-002",
        attack_type="Parameter Manipulation",
        description="Excessively long parameter value (potential buffer overflow probe)",
        severity="MEDIUM",
        base_confidence=55,
        patterns=_p(
            r"[A-Za-z0-9+/=]{512,}",    # long base64-like or encoded string
            r"[^\s]{600,}",              # very long token
        ),
        recommended_action=(
            "1. Enforce maximum parameter length limits.\n"
            "2. Investigate if application crashes or behaves abnormally."
        ),
    ),
    AttackRule(
        rule_id="PARAM-003",
        attack_type="Parameter Manipulation",
        description="Encoded payload patterns (%xx sequences)",
        severity="LOW",
        base_confidence=40,
        patterns=_p(
            r"(%[0-9a-f]{2}){5,}",      # ≥5 consecutive URL-encoded chars
        ),
        recommended_action=(
            "1. Decode and inspect the payload.\n"
            "2. Cross-check with other detection rules."
        ),
    ),
]

# ---------------------------------------------------------------------------
# ALL RULES REGISTRY
# ---------------------------------------------------------------------------

ALL_RULES: List[AttackRule] = (
    SQLI_RULES
    + XSS_RULES
    + PATH_TRAVERSAL_RULES
    + CMDI_RULES
    + PARAM_RULES
)

RULE_MAP = {r.rule_id: r for r in ALL_RULES}
