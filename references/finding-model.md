# Finding Model

## Type

- **Defect** — viola uma regra explícita de `POLICY.md`. Não subjectivo.
- **Concern** — risco real não coberto por POLICY. Requer julgamento.
- **Suggestion** — melhoria de qualidade que não bloqueia release.

## Severity

- **Blocker** — impede a skill de funcionar ou introduz risco de segurança. Verdict → `Reject`.
- **Major** — degrada qualidade / triggering / correctness. Verdict ≥ `Needs revision`.
- **Minor** — problema real mas contornável. Verdict pode ficar `Approve with nits`.
- **Nit** — estilo, wording, formatação.

## Confidence

- **Observed** — findado directamente no ficheiro; evidence cita linha + trecho literal.
- **Inferred** — deduzido de evidência circumstancial (dependência em ficheiro ausente, comportamento provável).
- **Unknown** — não verificável no âmbito da review; regista para o leitor decidir.

**Regra do leitor:**
- `Observed` → aplicar fix sem discussão adicional.
- `Inferred` → confirmar com o autor antes de aplicar.
- `Unknown` → tratar como TODO de discovery, não como acção.

## Verdict enum

Ordem de precedência (maior severity manda, não contagem):

| Verdict | Condição |
|---|---|
| `Reject` | ≥1 Blocker |
| `Needs revision` | 0 Blockers, ≥1 Major |
| `Approve with nits` | 0 Blockers, 0 Majors, ≥1 Minor |
| `Ready with suggestions` | Só Suggestions |
| `Ready` | Zero findings |

## Anti-patterns em findings

- Finding sem evidence literal → colapsa para Confidence `Unknown` e não é acionável.
- Fundir Defect e Concern → policy fica invisível.
- Múltiplos findings do mesmo problema → juntar num único com sub-bullets.
- Severity inflado ("Blocker" para wording) → o operador perde confiança no auditor.
