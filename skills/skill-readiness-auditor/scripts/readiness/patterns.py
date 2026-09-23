"""Every regular expression the checks share, and the model-profile phrases."""

from __future__ import annotations

import re


# Claude Code also accepts a full model id (`claude-opus-5-5`).
CLAUDE_MODEL_ID_RE = re.compile(r"^claude-[a-z0-9-]+$")

# A reference starts a path: `scripts/x.py`, or a sibling skill's file as
# `../other-skill/scripts/x.py`. Preceded by `/` it is the tail of a longer
# path (`<plugin>/skills/a/scripts/x.py`) and is not this skill's resource.
RESOURCE_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9_./<>-])"
    r"((?:\.\./[A-Za-z0-9_.-]+/)?"
    r"(?:references|scripts|assets|templates|schemas|baselines)/"
    r"[A-Za-z0-9_./*?{}\[\]-]+)"
)

# `<plugin>/scripts/x.py` names a resource shipped at the plugin root, shared
# by every skill of the plugin: the declared shared-resource root of §16.
PLUGIN_RESOURCE_RE = re.compile(
    r"<plugin>/"
    r"((?:skills/[A-Za-z0-9_.-]+/)?"
    r"(?:references|scripts|assets|templates|schemas|baselines)/"
    r"[A-Za-z0-9_./*?{}\[\]-]+)"
)

ABSOLUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:"
    r"[A-Za-z]:\\(?:[A-Za-z0-9_. -]+\\)*[A-Za-z0-9_. -]+"
    r"|"
    r"/(?:home|Users|mnt|opt|srv|var|tmp)/"
    r"[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+ -]+)*"
    r")"
)

URL_RE = re.compile(
    r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
    re.IGNORECASE,
)

SHELL_EXECUTION_RE = re.compile(
    r"(?m)(?:^|[`$]\s*)"
    r"(?:bash|sh|zsh|fish|powershell|pwsh|cmd|python3?|node|npm|npx|pnpm|yarn)"
    r"\s+[^\n`]+"
)

DEPENDENCY_INSTALL_RE = re.compile(
    r"\b(?:pip(?:3)?\s+install|npm\s+install|npm\s+i\b|"
    r"pnpm\s+(?:add|install)|yarn\s+add|uv\s+(?:add|pip\s+install)|"
    r"apt(?:-get)?\s+install|brew\s+install)\b",
    re.IGNORECASE,
)

ENVIRONMENT_ACCESS_RE = re.compile(
    r"\b(?:process\.env|os\.environ|os\.getenv|System\.getenv|"
    r"\$ENV:|\$\{?[A-Z][A-Z0-9_]{2,}\}?)",
    re.IGNORECASE,
)

CREDENTIAL_ACCESS_RE = re.compile(
    r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|"
    r"credential|private[_-]?key|\.env|id_rsa|id_ed25519)\b",
    re.IGNORECASE,
)

DYNAMIC_IMPORT_RE = re.compile(
    r"\b(?:importlib\.import_module|__import__|dynamic\s+import|"
    r"import\s*\(|require\s*\([^'\"]|eval\s*\(|exec\s*\()",
    re.IGNORECASE,
)

ENCODED_CONTENT_RE = re.compile(
    r"\b(?:base64\s+(?:-d|--decode)|fromhex\s*\(|"
    r"atob\s*\(|decode64|xxd\s+-r)\b",
    re.IGNORECASE,
)

MCP_RE = re.compile(
    r"\b(?:MCP|Model Context Protocol|mcpServers|mcp-server|mcp_server)\b",
    re.IGNORECASE,
)

AUDIT_MANIPULATION_RE = re.compile(
    r"(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+"
    r"(?:rules|instructions)|"
    r"(?:return|mark\s+as)\s+(?:only\s+)?ready|"
    r"skip\s+(?:the\s+)?(?:audit|verification)|"
    r"do\s+not\s+(?:report|list)\s+findings|"
    r"pre[- ]approved|"
    r"trust\s+mode|"
    r"bypass\s+(?:the\s+)?(?:audit|review)",
    re.IGNORECASE,
)

NETWORK_TOOL_RE = re.compile(
    r"\b(?:WebFetch|curl|wget|fetch\s*\(|requests\.|httpx\.|axios\.|"
    r"https?\.request\s*\(|urllib\.request|Invoke-WebRequest)\b",
    re.IGNORECASE,
)

MANDATORY_ALTERNATIVE_RE = re.compile(
    r"\b(?:use|usar|utilize|invoke|hand\s+off\s+to)\s+"
    r"`?([a-z0-9]+(?:-[a-z0-9]+)+)`?",
    re.IGNORECASE,
)

BASH_COMMAND_RE = re.compile(
    r"(?m)(?:^|\n|`|\$)\s*"
    r"((?:bash|sh|zsh|python3?|node|npm|npx|pnpm|yarn)\s+"
    r"[A-Za-z0-9_./-]+(?:\s+[^\n`]*)?)"
)

# (pattern, operational effect, severity, replacement). Sources, dated, in
# references/model-profiles.md: Anthropic's prompting pages for Claude Opus 5,
# Sonnet 5 and the current-model best practices.
PROFILE_PHRASES = {
    "claude": [
        (
            re.compile(r"\bCRITICAL\s*:|\bYOU\s+MUST\b|\bMUST\s+ALWAYS\b"),
            "aggressive emphasis written for older models makes current models over-trigger",
            "Minor",
            "State the condition in plain words: 'Use X when ...'.",
        ),
        (
            re.compile(
                r"\b(?:if|when)\s+in\s+doubt,?\s+(?:use|run|call|invoke|load)\b|"
                r"\bdefault\s+to\s+using\b|"
                r"\bem\s+caso\s+de\s+d[úu]vida,?\s+(?:usa|corre|chama)\b",
                re.I,
            ),
            "a blanket default makes current models over-trigger the tool or skill",
            "Minor",
            "Name the situations where the tool helps instead of a default.",
        ),
        (
            re.compile(
                r"\bdouble[- ]check\b|\bre-?verify\b|\bverify\s+your\s+(?:work|answer)\b|"
                r"\bcheck\s+your\s+work\b|\buse\s+a\s+subagent\s+to\s+(?:verify|double[- ]check|review)\b|"
                r"\bverifica(?:r)?\s+(?:tudo\s+)?duas\s+vezes\b|\bvolta\s+a\s+verificar\b",
                re.I,
            ),
            "current Claude models already self-verify; an explicit re-check instruction causes over-verification",
            "Minor",
            "Remove it, or replace it with a concrete gate: 'Continue only when <command> exits 0'.",
        ),
        (
            re.compile(
                r"\bonly\s+report\s+(?:the\s+)?(?:high|critical)(?:[- ]severity)?\b|\bbe\s+conservative\b|"
                r"\bdo(?:\s+not|n'?t)\s+nitpick\b|\breporta\s+s[óo]\s+(?:o\s+)?(?:grave|cr[íi]tico)",
                re.I,
            ),
            "Sonnet 5 and Opus 5 follow a self-filter literally and drop real findings",
            "Minor",
            "Name the bar concretely ('report anything that could cause incorrect behaviour; omit pure style').",
        ),
        (
            re.compile(r"\b(?:do\s+not|don'?t)\s+(?:think|reason)\b|\bwithout\s+thinking\b", re.I),
            "an instruction not to think increases internal-tag leakage when thinking is disabled",
            "Minor",
            "Remove it; control cost with effort, not with an instruction.",
        ),
        (
            re.compile(r"\bafter\s+every\s+\d+\s+tool\s+calls?\b", re.I),
            "forced progress narration is scaffolding current models no longer need",
            "Nit",
            "Describe the update you want instead of a fixed cadence.",
        ),
    ],
}


DISALLOWED_TOOLS_RE = re.compile(
    r"^disallowed-tools:\s*(?:.*?)(?=^\S|\Z)",
    re.M | re.S,
)


MARKDOWN_LINK_RE = re.compile(r"\]\((?!https?:|#|mailto:)([^)#\s]+\.md)\)")
TOC_RE = re.compile(r"^(?:#{1,3}\s*)?(?:contents|table\s+of\s+contents|[íi]ndice|contenido|sum[áa]rio)\b",
                    re.I | re.M)


READ_ONLY_RE = re.compile(r"\bread[- ]only\b", re.I)
# "not read-only", "não é read-only", "no es read-only", "isn't read-only".
NEGATED_BEFORE_RE = re.compile(
    r"\b(?:not|never|isn'?t|no|n[ãa]o|nao|nunca)\b(?:\s+(?:is|é|e|es|a|um|uma))?\s*$",
    re.I,
)


# Hard limits of the Agent Skills format (Anthropic, "Skill authoring best
# practices"): the harness rejects or truncates past them.
NAME_MAX, DESCRIPTION_MAX = 64, 1024
RESERVED_NAME_RE = re.compile(r"anthropic|claude")
XML_TAG_RE = re.compile(r"<[A-Za-z/][^<>]*>")
PERSON_RE = re.compile(
    r"^\s*(?:I|I'm|I'll|We|You|Eu|Posso|Podes|Puedo|Puedes)\b|"
    r"\b(?:I\s+can|I\s+will|you\s+can\s+use\s+this)\b",
    re.I,
)
MONTHS = (r"(?:January|February|March|April|May|June|July|August|September|October|"
          r"November|December|janeiro|fevereiro|mar[çc]o|abril|maio|junho|julho|agosto|"
          r"setembro|outubro|novembro|dezembro)")
TIME_SENSITIVE_RE = re.compile(
    r"\b(?:before|after|until|as\s+of|since|antes\s+de|depois\s+de|at[ée])\s+"
    + MONTHS + r"(?:\s+de)?\s+20\d\d\b|\bas\s+of\s+20\d\d\b",
    re.I,
)
