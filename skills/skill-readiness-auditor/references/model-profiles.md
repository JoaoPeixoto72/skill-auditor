# Model profiles

Version: 1.0.0

Model profiles define instruction patterns that may improve or degrade an Agent Skill when used with a particular model family.

They are readiness guidance, not security policy.

A model-fit finding requires:

1. an active profile;
2. literal evidence from the target;
3. an operational impact;
4. a concrete replacement.

Do not apply profile-specific findings when the active profile is `generic`.

---

## 1. Profile resolution

Resolve the profile in this order:

1. explicit `--model`;
2. target skill frontmatter `model:`;
3. `generic`.

The report MUST record the source:

```text
Model profile: sol5.6
Resolved from: --model
```

or:

```text
Model profile: opus5
Resolved from: frontmatter model: opus
```

or:

```text
Model profile: generic
Resolved from: fallback
```

---

## 2. Model identifier mapping

Use this default mapping unless the repository declares another mapping.

| Frontmatter model | Readiness profile |
|---|---|
| `opus` | `opus5` |
| `sonnet` | `generic` |
| `haiku` | `generic` |
| `inherit` | `generic` |
| absent | `generic` |

Explicit audit arguments MAY select:

- `generic`;
- `sol5.6`;
- `gemini3.8`;
- `opus5`.

A readiness profile name is not necessarily a valid harness model identifier.

Do not propose:

```yaml
model: generic
```

unless the target harness explicitly supports `generic` as a model identifier.

Do not propose:

```yaml
model: sol5.6
```

unless the target harness explicitly recognizes that identifier.

Profile selection belongs to the audit invocation. Runtime model selection belongs to the harness.

---

## 3. Universal instruction principles

These principles apply to every profile.

### Prefer explicit conditions

Prefer:

```text
If a referenced path does not exist, record a Major finding.
```

Avoid:

```text
Handle missing paths appropriately.
```

### Prefer bounded procedures

Prefer:

```text
Inspect at most five skills per semantic-review batch.
```

Avoid:

```text
Inspect as many skills as necessary.
```

### Prefer observable outcomes

Prefer:

```text
Run the parser. If it exits non-zero, report invalid frontmatter.
```

Avoid:

```text
Ensure the frontmatter looks valid.
```

### Separate rules from examples

Rules define required behavior.

Examples illustrate rules but do not silently introduce new requirements.

### Define failure behavior

A workflow SHOULD state what happens when:

- a command is unavailable;
- parsing fails;
- a file is missing;
- output is partial;
- the target is ambiguous;
- a verification cannot be performed safely.

### Avoid contradictory authority

Do not combine instructions such as:

```text
Never ask questions.
```

and:

```text
Ask for clarification whenever information is missing.
```

Replace them with an ordered rule:

```text
Resolve information from local evidence first. Ask one focused question only when the task cannot proceed safely without it.
```

---

## 4. `generic`

Use `generic` when:

- no profile is selected;
- the model cannot be resolved;
- the target is intended for multiple model families;
- only universal defects should be reported.

### Evaluate

- clarity;
- explicit inputs;
- explicit outputs;
- ordering;
- boundedness;
- contradictions;
- failure behavior;
- tool consistency;
- workflow coverage.

### Do not report as profile defects

Do not reject phrases solely because a particular model family may dislike them.

Examples:

- “verify your work”;
- “double-check”;
- “be thorough”;
- “think carefully”.

Under `generic`, report them only when they create:

- an unbounded loop;
- contradiction;
- unverifiable behavior;
- unnecessary repetition;
- an unclear completion condition.

### Example

Potentially acceptable:

```text
Verify the generated JSON against the schema before returning it.
```

Defective because unbounded:

```text
Keep checking your work until you are completely certain.
```

---

## 5. `sol5.6`

Use for the Sol 5.6 reasoning profile.

This profile performs best with:

- explicit acceptance criteria;
- finite verification passes;
- direct task decomposition;
- observable completion conditions;
- clear separation between evidence and inference;
- minimal repetition.

### Problematic patterns

#### Circular verification

Examples:

```text
Verify your work.
```

```text
Double-check everything.
```

```text
Review the result again until it is correct.
```

These phrases do not define:

- what to inspect;
- how many passes to perform;
- what failure looks like;
- when to stop.

#### Unbounded reasoning requests

Examples:

```text
Think step by step about every possible issue.
```

```text
Be maximally thorough.
```

```text
Consider all possible interpretations.
```

These instructions may increase latency and context use without improving the final evidence.

#### Repeated global reconsideration

Example:

```text
After every finding, reconsider the complete audit from the beginning.
```

Prefer incremental state updates instead.

### Preferred replacements

Replace:

```text
Double-check that every link resolves.
```

with:

```text
For each local link, resolve it against the skill directory. Record every unresolved path.
```

Replace:

```text
Verify your work before returning.
```

with:

```text
Before returning, confirm that the report contains a verdict, findings table, skipped-check list, and security footer.
```

Replace:

```text
Think carefully about portability.
```

with:

```text
Check path syntax, shell assumptions, interpreter availability, and adapter-specific tools. Report each unsupported assumption.
```

### Severity

Use Major when an unbounded or circular instruction affects the central workflow.

Use Minor when the phrase is localized and completion remains clear.

Use Suggestion when the replacement is only an efficiency improvement.

---

## 6. `gemini3.8`

Use for the Gemini 3.8 reasoning profile.

This profile benefits from:

- explicit source priority;
- bounded checklists;
- clear output schemas;
- direct conflict-resolution rules;
- named completion criteria;
- reduced instruction duplication.

### Problematic patterns

#### Broad self-review requests

Examples:

```text
Review everything again.
```

```text
Check whether you missed anything.
```

Without a bounded checklist, these instructions may produce repetitive passes.

#### Competing instruction lists

The same requirement repeated with different wording in multiple sections can lead to inconsistent prioritization.

Example:

```text
Always stop on the first error.
```

Later:

```text
Always continue and report every error.
```

#### Implicit source authority

Example:

```text
Use whichever document seems most relevant.
```

Prefer an explicit order:

```text
Use POLICY.md as authoritative. Use references for interpretation and examples.
```

#### Undefined structured output

Example:

```text
Return a useful report.
```

Prefer:

```text
Return Markdown containing Metadata, Summary, Findings, Claims, and Meta sections.
```

### Preferred replacements

Replace:

```text
Be thorough and check everything twice.
```

with:

```text
Run one structural pass and one claims pass. Do not repeat a pass unless its evidence is incomplete.
```

Replace:

```text
Use the relevant rules.
```

with:

```text
Apply POLICY.md first. If an example conflicts with POLICY.md, follow POLICY.md and report the conflict.
```

Replace:

```text
Return the best format.
```

with:

```text
Return Markdown unless --format json was requested.
```

### Severity

Contradictory source priority affecting normal execution → Major.

Undefined output when output structure is central → Major.

Repeated but consistent instructions → Minor or Suggestion.

---

## 7. `opus5`

Use for the Opus 5 high-agency profile.

This profile benefits from:

- explicit scope boundaries;
- strong state-transition gates;
- clear authorization requirements;
- outcome-based instructions;
- freedom inside bounded constraints;
- explicit conditions before consequential actions.

### Problematic patterns

#### Instructions to bypass validation

Examples:

```text
Skip verification.
```

```text
Assume the command succeeds.
```

```text
Trust the first result.
```

```text
Continue even if the gate fails.
```

These remove necessary execution boundaries.

#### Ambiguous autonomy

Examples:

```text
Make any changes needed.
```

```text
Use whatever tools are useful.
```

```text
Do anything necessary to finish.
```

When the skill is intended to be read-only or narrowly scoped, these phrases conflict with the permission contract.

#### State mutation without authorization

Example:

```text
If the report looks acceptable, mark the skill trusted.
```

Prefer:

```text
Emit enrolment evidence. Only the privileged release process may change Trust Registry state.
```

#### Verification without an action gate

Example:

```text
Check the command result and continue.
```

Prefer:

```text
Continue only when the command exits zero and the expected output field is present. Otherwise record a finding and stop the dependent branch.
```

### Corrective instructions

For this profile, explicit verification is often beneficial when it defines:

- evidence;
- pass condition;
- failure action;
- mutation boundary.

Do not report:

```text
Verify the file exists before using it.
```

as a defect.

The problematic form is:

```text
Assume the file exists and continue.
```

### Preferred replacements

Replace:

```text
Use any tools necessary.
```

with:

```text
Use only the tools declared in allowed-tools. If they are insufficient, report the blocked step.
```

Replace:

```text
Make the required fixes.
```

with:

```text
This skill is read-only. Report proposed fixes without editing the target.
```

Replace:

```text
Continue despite verification errors.
```

with:

```text
If verification fails, stop the dependent branch and record the failure.
```

### Severity

Skipped validation before state mutation → Major or Blocker, depending on impact.

Unbounded autonomy conflicting with a read-only contract → Major.

Localized vague autonomy with no available mutation tools → Minor.

---

## 8. Cross-profile comparison

| Pattern | generic | sol5.6 | gemini3.8 | opus5 |
|---|---|---|---|---|
| `verify your work` | Context-dependent | Replace with finite criteria | Replace with bounded pass | Accept only with a concrete gate |
| `double-check everything` | Concern if unbounded | Problematic | Problematic | Weak unless bounded |
| `think step by step` | Usually unnecessary | Problematic | Prefer task decomposition | Avoid requesting hidden reasoning |
| `skip verification` | Defect when verification is required | Defect | Defect | Strong defect |
| `assume it works` | Defect when branching depends on it | Defect | Defect | Strong defect |
| explicit command assertion | Preferred | Preferred | Preferred | Preferred |
| explicit failure action | Preferred | Preferred | Preferred | Required before consequential action |
| repeated policy text | Minor concern | Context inefficiency | Priority ambiguity | May weaken scope boundaries |

---

## 9. Model-fit finding format

Use:

```text
[Severity · Defect · Observed] Instruction conflicts with the active model profile

Evidence: SKILL.md:42 — "Double-check everything before returning."
Profile: sol5.6, resolved from --model
Impact: The instruction creates an unbounded global verification pass with no completion criterion.
Fix: Replace it with a finite checklist of required report sections.
Owner: Readiness
```

A valid model-fit finding MUST identify:

- literal phrase;
- profile;
- profile-resolution source;
- operational consequence;
- replacement.

---

## 10. Profile fallback

When a model identifier cannot be mapped:

```text
Declared model: custom-reasoner-v4
Resolved profile: generic
Reason: No profile mapping exists.
```

Report the identifier as unresolvable only when the target harness also cannot resolve it.

If the harness supports the model but the readiness auditor lacks a profile:

- do not report the model field as invalid;
- use `generic`;
- record a profile-coverage limitation.

---

## 11. Unsupported claims

The readiness auditor MUST NOT claim:

- a wording pattern always improves output;
- a profile guarantees correctness;
- a model will expose or conceal internal reasoning;
- a specific phrase causes a precise latency increase;
- a profile is universally superior.

Model-fit conclusions are scoped to the profile guidance and the reviewed workflow.

---

## 12. Updating profiles

A profile update SHOULD include:

1. model-family identifier;
2. applicable harness mappings;
3. problematic patterns;
4. preferred replacements;
5. severity guidance;
6. positive and negative fixtures;
7. evidence supporting the change;
8. version-history entry.

Do not silently change profile behavior through examples alone.
