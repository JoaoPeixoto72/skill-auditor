"""Every regular expression the project-policy line uses."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


# Fence languages whose content an agent or shell can execute. A ```text or
# ```json block in a policy document is an illustration, not behavior.
EXECUTABLE_FENCE_LANGUAGES = {
    "bash", "sh", "shell", "zsh", "console", "powershell", "ps1", "pwsh",
    "python", "py", "js", "javascript", "ts", "typescript", "node",
    "ruby", "rb", "perl", "php",
}

# Negation inverts the sentence that contains it: "the skill does not modify
# the Trust Registry" is not a mutation claim. An author gains nothing by
# writing it falsely, so it may appear on the matched line itself.
NEGATION_RE = re.compile(
    r"\b(?:cannot|can\s+not|can't|must\s+not|may\s+not|will\s+not|won't|"
    r"shall\s+not|should\s+not|do\s+not|does\s+not|did\s+not|don't|doesn't|"
    r"never|no\s+longer|without|forbidden|prohibited|disallow\w*|"
    r"not\s+permitted|not\s+allowed|refuse\w*|denies|denied|deny|"
    r"non-?goals?)\b",
    re.I,
)

# Exemplification only frames the text around it. "For example, <payload>" is
# an assertion an attacker can make for free, so it counts only when it comes
# from the list lead-in or the section heading — structure the payload line
# cannot forge on its own.
EXEMPLIFICATION_RE = re.compile(
    r"\b(?:detect\w*|indicator\w*|"
    r"example\w*|counter-?example\w*|fixture\w*|illustrat\w*|sample\w*|"
    r"attempts?\s+to|attempting\s+to|untrusted|"
    r"review\w*\s+for|inspect\w*\s+for|check\w*\s+for)\b",
    re.I,
)

# A structured declaration that switches a capability off, for example
# `target-may-disable-runtime-gate: false` in instruments.yaml.
NEGATED_DECLARATION_RE = re.compile(
    r"^\s*(?:-\s*)?[\"']?[\w.$-]+[\"']?\s*[:=]\s*"
    r"[\"']?(?:false|no|none|never|off|0|denied|blocked|forbidden)[\"']?\s*,?\s*$",
    re.I,
)

LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.*)$")

# Requires a syntactically real authority so that shell globs such as the
# `http://*|https://*` guard in scripts/audit.sh are not read as destinations.
URL_RE = re.compile(
    r"https?://(?:[A-Za-z0-9][A-Za-z0-9-]*\.)*[A-Za-z0-9][A-Za-z0-9-]*"
    r"(?::\d{1,5})?"
    r"(?:[/?#][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?",
    re.I,
)

# Reserved and non-resolvable names (RFC 2606, RFC 6761) plus single-label
# hosts. A documentation URL on one of these is a placeholder, not a
# destination, and declaring it in a resource policy would be meaningless.
PLACEHOLDER_HOST_RE = re.compile(
    r"^(?:[^.]+|"
    r"(?:[\w-]+\.)*(?:invalid|example|test|localhost|local)|"
    r"(?:[\w-]+\.)*example\.(?:com|net|org))$",
    re.I,
)


def placeholder_host(url: str) -> bool:
    return bool(PLACEHOLDER_HOST_RE.match(urlsplit(url).hostname or ""))


MARKDOWN_IMAGE_RE = re.compile(
    r"!\[[^\]]*]\(\s*https?://[^)]+\)",
    re.I,
)

INJECTION_RE = re.compile(
    r"(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+"
    r"(?:rules|instructions)|"
    r"(?:return|mark\s+as)\s+(?:only\s+)?(?:ready|approve)|"
    r"skip\s+(?:the\s+)?(?:audit|verification)|"
    r"do\s+not\s+(?:report|list)\s+findings|"
    r"reveal\s+(?:the\s+)?system\s+prompt|"
    r"bypass\s+(?:the\s+)?runtime\s+gate|"
    r"modify\s+(?:the\s+)?trust\s+registry",
    re.I,
)

OBFUSCATION_RE = re.compile(
    r"base64\s+(?:-d|--decode).*?\|\s*(?:bash|sh|python|node)|"
    r"\b(?:eval|exec)\s*\([^)]*(?:base64|fromhex|atob)|"
    r"\bxxd\s+-r.*?\|\s*(?:bash|sh)",
    re.I | re.S,
)

NETWORK_RE = re.compile(
    r"\b(?:WebFetch|curl|wget|Invoke-WebRequest)\b|"
    r"\bfetch\s*\(|"
    r"\brequests\.(?:get|post|put|delete|request)\s*\(|"
    r"\bhttpx\.(?:get|post|put|delete|request)\s*\(|"
    r"\baxios\.(?:get|post|put|delete|request)\s*\(|"
    r"\bhttps?\.request\s*\(",
    re.I,
)

SENSITIVE_RE = re.compile(
    r"\b(?:process\.env|os\.environ|os\.getenv|\.env|"
    r"api[_-]?key|access[_-]?token|session[_-]?cookie|"
    r"id_rsa|id_ed25519|private[_-]?key|credential)\b",
    re.I,
)

# Persistence requires an operation, not a topic. A bare word such as
# "startup" appears in any document that discusses persistence and is not
# evidence of it.
PERSISTENCE_RE = re.compile(
    r"\bcrontab\s+-[el]\b|"
    r"\b(?:>>?|tee|cp|mv|echo\b.*>>?)\s*[^\n]{0,40}"
    r"(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|/cron\.d/|"
    r"LaunchAgents/|LaunchDaemons/)|"
    r"\blaunchctl\s+(?:load|bootstrap|enable)\b|"
    r"\bsystemctl\s+(?:--user\s+)?enable\b|"
    r"\bschtasks\s+/create\b|"
    r"\bNew-ScheduledTask\b|"
    r"\bRegister-ScheduledJob\b",
    re.I,
)

# Bounded to a single line: a prose paragraph that mentions the Runtime Gate
# and, two sentences later, the word "modify" is not a mutation capability.
REGISTRY_TAMPER_RE = re.compile(
    r"(?:write|edit|modify|replace|delete|reset|clear)[^\n]{0,60}?"
    r"(?:trust[- ]registry|runtime[- ]gate)|"
    r"(?:trust[- ]registry|runtime[- ]gate)[^\n]{0,60}?"
    r"(?:write|edit|modify|replace|delete|reset|clear)",
    re.I,
)

MUTABLE_DEPENDENCY_RE = re.compile(
    r"(?:git\+https?://|https?://).{0,200}"
    r"(?:@main|@master|/main/|/master/|/latest/)|"
    r"\b(?:pip|npm|pnpm|yarn|uv).{0,80}(?:install|add)\s+"
    r"[A-Za-z0-9_.@/-]+(?:\s|$)",
    re.I,
)


# A network tool granted in frontmatter is a capability. The same name under
# `disallowed-tools` is the opposite claim and must not count.
ALLOWED_TOOLS_RE = re.compile(
    r"^allowed-tools:\s*(.*?)(?=^\S|\Z)",
    re.M | re.S,
)
