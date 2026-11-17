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
# references/model-profiles.md: Anthropic's prompting pages for current Claude
# models (Fable 5.2, Opus 5.5, Opus 5, Sonnet 5) and Claude Code's best
# practices. All-caps emphasis is counted per file by EMPHASIS_RE instead, so
# fifty `MUST`s are one finding, not fifty.
PROFILE_PHRASES = {
    "claude": [
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
                r"\bdouble[- ]check\s+(?:everything|all|your)\b|\bre-?verify\s+everything\b|"
                r"\bverify\s+your\s+(?:work|answer)\b|\bcheck\s+your\s+work\b|"
                r"\bverifica(?:r)?\s+(?:tudo\s+)?duas\s+vezes\b|\bvolta\s+a\s+verificar\s+tudo\b",
                re.I,
            ),
            "a re-check with no criterion makes current models over-verify; what helps is a check that "
            "comes back pass or fail",
            "Minor",
            "Name the check: 'Continue only when <command> exits 0'. A fresh-context reviewer "
            "(a subagent, /code-review) is a different thing and stays.",
        ),
        (
            re.compile(
                r"\bthink\s+(?:hard(?:er)?|carefully|deeply|step[- ]by[- ]step)\b|"
                r"\bbe\s+(?:very\s+|extremely\s+)?thorough\b|"
                r"\bpensa\s+(?:bem|com\s+cuidado|passo\s+a\s+passo)\b|\bs[eê]\s+minucioso\b",
                re.I,
            ),
            "effort is the control for reasoning depth; these words are ordinary prompt text, and on "
            "Opus 5.5 a line asking to think carefully delayed replies with no clear quality gain",
            "Minor",
            "Remove it and set `effort:` in the frontmatter (or `ultrathink` for one turn).",
        ),
        (
            re.compile(
                r"\b(?:do\s+not|don'?t)\s+be\s+lazy\b|\bkeep\s+going\s+until\b|"
                r"\bloop\s+until\s+(?:done|finished|complete)\b|\b(?:do\s+not|don'?t)\s+stop\s+until\b|"
                r"\bn[ãa]o\s+sejas?\s+pregui[çc]oso\b|\bn[ãa]o\s+pares\s+at[ée]\b",
                re.I,
            ),
            "current models carry an agreed task through on their own; anti-laziness lines cause "
            "over-work instead of fixing a stall",
            "Minor",
            "Give a pass/fail finish line ('done when <command> exits 0'); enforce it with /goal or a "
            "Stop hook that exits 2.",
        ),
        (
            re.compile(
                r"\b(?:write|show|output|print|include)\s+(?:out\s+)?(?:all\s+)?(?:of\s+)?(?:your|the)\s+"
                r"(?:full\s+|complete\s+|internal\s+|entire\s+)?"
                r"(?:reasoning|chain[- ]of[- ]thought|thought\s+process|thinking)\b|"
                r"\bthink\s+out\s+loud\b|\bmostra\s+(?:o\s+)?(?:teu\s+|todo\s+o\s+)?racioc[íi]nio\b",
                re.I,
            ),
            "Opus 5.5 and Fable 5.2 can decline a request that pushes the model to reproduce its "
            "reasoning in the response (refusal category reasoning_extraction)",
            "Major",
            "Ask for a short explanation of the answer or a summary of the actions taken; read the "
            "reasoning from summarized thinking blocks.",
        ),
        (
            re.compile(
                r"\balways\s+(?:use|spawn|launch|start|delegate\s+to)\s+(?:a\s+|one\s+or\s+more\s+|"
                r"several\s+|multiple\s+)?(?:parallel\s+)?sub-?agents?\b|"
                r"\bdelegate\s+(?:every|each|all)\b|\bdelega\s+sempre\b|\busa\s+sempre\s+(?:um\s+)?sub-?agentes?\b",
                re.I,
            ),
            "Fable 5.2 delegates readily when prompts invite it; a standing instruction to delegate "
            "raises session cost without improving the answer",
            "Minor",
            "Say when a subagent is worth its cost (independent parallel work, a fresh reviewer) and "
            "how to brief it.",
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
            re.compile(
                r"\b(?:do\s+not|don'?t)\s+(?:think|reason|deliberate)\b|\bwithout\s+(?:thinking|deliberating)\b",
                re.I,
            ),
            "thinking is always on in Opus 5.5, and on Fable 5.2 such a line did not stop thinking at "
            "medium effort and above",
            "Minor",
            "Remove it; lower `effort:` instead.",
        ),
    ],
}

# All-caps emphasis: IMPORTANT, CRITICAL, NEVER, ALWAYS, MUST, DO NOT. Claude
# Code's best practices list "Add IMPORTANT or ALL CAPS" under advice to stop
# following: current models over-apply an emphasised rule. Inline code and
# fenced blocks are excluded by the check (identifiers such as `CRITICAL`).
EMPHASIS_RE = re.compile(
    r"(?<![A-Za-z_`])(?:IMPORTANT|CRITICAL|NEVER|ALWAYS|MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|"
    r"DO\s+NOT|DON'T|YOU\s+MUST|NUNCA|SEMPRE|OBRIGAT[ÓO]RIO)(?![A-Za-z_`])"
)

# An imperative line that opens with "Never" and gives no scope or reason.
# Fable 5.2 treats "never" as absolute; its prompting page asks for the scope
# and the reason, or an approval rule ("ask before deleting files").
# Capitalised only: a line that starts a sentence, not the wrapped tail of one.
BARE_NEVER_RE = re.compile(r"(?m)^[ \t]*(?:[-*][ \t]+|\d+\.[ \t]+)?(?:Never|Nunca)\b(?P<rest>[^\n]*)$")
NEVER_REASON_RE = re.compile(
    r"\b(?:because|since|unless|except|so\s+that|otherwise|porque|exceto|a\s+menos|sen[ãa]o)\b|[:—]|\s-\s",
    re.I,
)

# A prohibition in prose whose subject cannot be taken back if the model gets it
# wrong once (Lydia Hallie, "Rethinking Claude Code best practices"; Claude
# Code best practices, "Enforce the rules that can't have exceptions").
# category -> (target pattern, tokens in disallowed-tools that back it).
PROHIBITION_RE = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|nunca|n[ãa]o)\b[^.\n]{0,90}?"
    r"(?P<target>\.env\b|secrets?\b|credentials?\b|api[ _-]?keys?\b|ssh\s+keys?|id_rsa|"
    r"rm\s+-rf|delete\b|apag\w*|elimin\w*|"
    r"(?:force[- ])?push\b|git\s+push|"
    r"deploy\w*|publish\w*|send\s+(?:an?\s+)?(?:e-?mails?|messages?)|envi\w+\s+(?:e-?mails?|mensage\w+)|"
    r"drop\s+table|"
    r"execute\b|run\s+(?:the\s+)?(?:target|untrusted)|execut\w+|"
    r"install\s+(?:dependencies|packages)|instal\w+\s+depend\w+|"
    r"fetch\w*\s+(?:urls?|remote)|download\w*)",
    re.I,
)
HARD_RULE_TOKENS = {
    "secret": (r"\.env|secret|credential|api[ _-]?key|ssh|id_rsa", ("Read(",)),
    "delete": (r"rm\s+-rf|delete|apag|elimin", ("Bash(rm",)),
    "push": (r"push", ("Bash(git push",)),
    "outbound": (r"deploy|publish|send|envi|drop\s+table", ()),
    "execute": (r"execut|run\s", ()),
    "install": (r"install|instal", ("install",)),
    "network": (r"fetch|download", ("WebFetch", "Bash(curl")),
}

# Commands with an effect outside the working copy. A skill that runs one should
# not start on the model's own judgment (Claude Code best practices: "For a
# workflow with side effects ... add disable-model-invocation: true").
SIDE_EFFECT_COMMAND_RE = re.compile(
    r"\b(?:git\s+push|npm\s+publish|pnpm\s+publish|yarn\s+publish|cargo\s+publish|twine\s+upload|"
    r"gh\s+release\s+create|gh\s+pr\s+merge|kubectl\s+(?:apply|delete)|terraform\s+(?:apply|destroy)|"
    r"helm\s+(?:install|upgrade)|docker\s+push|vercel\s+(?:deploy|--prod)|netlify\s+deploy|"
    r"firebase\s+deploy|wrangler\s+(?:deploy|publish)|fly\s+deploy|aws\s+s3\s+(?:rm|sync)|"
    r"supabase\s+db\s+push|sendmail)\b",
    re.I,
)
NEGATION_RE = re.compile(r"\b(?:not|never|don'?t|no|without|n[ãa]o|nunca|sem)\b", re.I)

# Events where a hook is expected to stop something, and how a script says so.
BLOCKING_HOOK_EVENTS = {"PreToolUse", "Stop", "SubagentStop", "TaskCompleted", "UserPromptSubmit",
                        "PermissionRequest", "TeammateIdle"}
EXIT_ONE_RE = re.compile(r"\bexit\s+1\b|sys\.exit\(\s*1\s*\)|process\.exit\(\s*1\s*\)|\bexit\s+\$?\{?1\}?\s*$",
                         re.M)
BLOCKING_SIGNAL_RE = re.compile(
    r"\bexit\s+2\b|sys\.exit\(\s*2\s*\)|process\.exit\(\s*2\s*\)|permissionDecision|\"decision\"|"
    r"'decision'|exit\s+\$?\{?BLOCK",
)
HOOK_SCRIPT_RE = re.compile(r"([A-Za-z0-9_./${}-]+\.(?:sh|py|js|mjs|ts|ps1|rb))")


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
