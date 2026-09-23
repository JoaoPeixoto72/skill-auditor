"""Detectors for what English-only keyword rules miss.

SkillSpector lists non-English content as a known gap, and hidden Unicode
tags slip past a check that only knows the zero-width characters. This module
is where the project policy covers them: instruction overrides in Portuguese,
Spanish and French; instructions to conceal behaviour from the user;
instructions to deceive the auditor; invisible characters; and descriptions
that try to capture every request.

Concealment and audit deception are phrased as negations, so the caller must
not apply negation-based documentation suppression to them — that suppression
would exonerate the payload by its own grammar.
"""

from __future__ import annotations

import re

# Zero-width, bidirectional controls, invisible operators, a BOM that is not
# the first character, and the Unicode Tags block (ASCII smuggling).
INVISIBLE_RANGES = (
    (0x200B, 0x200D), (0x202A, 0x202E), (0x2060, 0x2064),
    (0x2066, 0x2069), (0xFEFF, 0xFEFF), (0xE0000, 0xE007F),
)

OVERRIDE_RE = re.compile(
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:the\s+)?"
    r"(?:previous|prior|above|earlier|user'?s?)\s+(?:rules|instructions|directions|prompts?)\b|"
    r"\b(?:ignor[ae]r?|esquece(?:r)?|desconsider[ae]r?)\s+(?:todas\s+)?(?:as\s+)?"
    r"(?:instru[çc][õo]es|regras|ordens)\s+(?:anteriores|acima|pr[ée]vias|do\s+utilizador|do\s+usu[áa]rio)\b|"
    r"\b(?:ignora(?:r)?|olvida(?:r)?)\s+(?:todas\s+)?(?:las\s+)?(?:instrucciones|reglas)\s+"
    r"(?:anteriores|previas|del\s+usuario)\b|"
    r"\bignore[rz]?\s+(?:toutes\s+)?les\s+(?:instructions|r[èe]gles)\s+"
    r"(?:pr[ée]c[ée]dentes|ant[ée]rieures)\b",
    re.I,
)

# "Without telling the user" also describes a UX defect ("search fails without
# telling the user"); it is an instruction only when the sentence opens with an
# imperative, which is how a step addressed to the agent is written.
_IMPERATIVE_EN = (r"(?:send|upload|copy|save|store|write|delete|remove|run|execute|"
                  r"install|modify|change|post|forward|collect|read|move)")
_IMPERATIVE_PT = (r"(?:envia|carrega|copia|guarda|grava|escreve|apaga|remove|corre|"
                  r"executa|instala|altera|muda|recolhe|l[êe]|move)")
_IMPERATIVE_ES = r"(?:env[íi]a|sube|copia|guarda|escribe|borra|ejecuta|instala|cambia|lee)"
_SENTENCE_START = r"(?:^|[.:;!?]\s+|^\s*(?:[-*+]|\d+[.)])\s+)"

CONCEALMENT_RE = re.compile(
    r"\b(?:do\s+not|don't|never)\s+(?:tell|show|mention|reveal|disclose)\s+"
    r"(?:this\s+|it\s+|anything\s+)?(?:to\s+)?the\s+user\b|"
    r"\bhide\s+(?:this|it)\s+from\s+the\s+user\b|"
    + _SENTENCE_START + _IMPERATIVE_EN
    + r"\b[^.\n]{0,80}?\bwithout\s+(?:telling|informing|asking|notifying)\s+the\s+user\b|"
    r"\bn[ãa]o\s+lhe\s+(?:mostres|mostre|digas|diga|contes|conte|reveles|revele)\b|"
    r"\bn[ãa]o\s+(?:mostres|mostre|digas|diga|contes|conte|reveles|revele)\b[^.\n]{0,40}?"
    r"\b(?:utilizador|usu[áa]rio)\b|"
    + _SENTENCE_START + _IMPERATIVE_PT
    + r"\b[^.\n]{0,80}?\bsem\s+(?:dizer|avisar|informar)\s+(?:ao|o)\s+(?:utilizador|usu[áa]rio)\b|"
    r"\bno\s+(?:le\s+)?(?:muestres|digas|reveles)\b[^.\n]{0,40}?\busuario\b|"
    + _SENTENCE_START + _IMPERATIVE_ES
    + r"\b[^.\n]{0,80}?\bsin\s+(?:decirle|avisar|informar)\s+al\s+usuario\b|"
    r"\bne\s+(?:le\s+)?(?:dis|montre|r[ée]v[èe]le)\s+pas\b[^.\n]{0,30}?\butilisateur\b",
    re.I | re.M,
)

AUDIT_DECEPTION_RE = re.compile(
    r"\bif\s+(?:an?|the)\s+(?:auditor|reviewer|scanner)\s+(?:asks|checks|looks)\b|"
    r"\b(?:tell|say\s+to|answer)\s+the\s+(?:auditor|reviewer)\b|"
    r"\b(?:report|mark|declare)\s+(?:this\s+skill\s+)?as\s+(?:safe|clean|approved|trusted)\b|"
    r"\bse\s+(?:um|o)\s+(?:auditor|revisor|scanner)\s+(?:perguntar|verificar|analisar)\b|"
    r"\b(?:diz|diga|responde)\s+ao\s+(?:auditor|revisor)\b|"
    r"\b(?:marca|declara|reporta)\s+(?:esta\s+skill\s+)?como\s+(?:segura|limpa|aprovada)\b|"
    r"\bsi\s+(?:un|el)\s+(?:auditor|revisor)\s+pregunta\b|"
    r"\bmarca\s+(?:esta\s+skill\s+)?como\s+(?:segura|limpia|aprobada)\b",
    re.I,
)

TRIGGER_HIJACK_RE = re.compile(
    r"\b(?:for|on)\s+(?:every|all|any)\s+(?:requests?|tasks?|prompts?|messages?)\b|"
    r"\balways\s+(?:use|activate|invoke|load)\s+this\s+skill\b|"
    r"\bbefore\s+any\s+other\s+skill\b|"
    r"\b(?:em|para)\s+(?:todos\s+os|qualquer)\s+(?:pedidos?|tarefas?|mensagens?)\b|"
    r"\bantes\s+de\s+qualquer\s+outra\s+skill\b|"
    r"\b(?:en|para)\s+(?:todas\s+las|cualquier)\s+(?:solicitudes|peticiones|tareas)\b",
    re.I,
)


def first_invisible(text: str) -> tuple[int, int] | None:
    """(offset, code point) of the first invisible character, or None."""
    for offset, character in enumerate(text):
        point = ord(character)
        if point == 0xFEFF and offset == 0:
            continue
        if any(low <= point <= high for low, high in INVISIBLE_RANGES):
            return offset, point
    return None


def description_of(text: str) -> tuple[str, int] | None:
    """The frontmatter description and its offset, if the file has one."""
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    match = re.search(r"^description:\s*(.+)$", text[:end if end > 0 else len(text)], re.M)
    return (match.group(1), match.start(1)) if match else None
