# Analysis modes

## Strict mode

`--strict` means:

- SkillSpector not installed → the project-policy line decides alone
  (`Hold` only with `--require-scanner`);
- incomplete evidence from an installed SkillSpector → `Hold`;
- failed scanner-trust verification → `Hold`, after every `Reject` rule;
- parser failure → `Hold`, or `Reject` when malicious evasion is indicated;
- skipped executable file → `Hold`;
- undeclared runtime URL → `Reject`;
- network capability without verified interception → `Hold` or `Reject`;
- unresolved Critical or Blocker → `Reject`;
- unresolved High or Major → at least `Hold`.

Strict mode is required before:

- installation from an untrusted source;
- publishing;
- signing;
- Trust Registry enrolment;
- quarantine release.

Without `--strict` the verdict never reaches `Eligible for enrolment`.

## Semantic mode

Static mode is the default. `--mode semantic` records that the operator
authorized the additional semantic review; the deterministic script itself
never contacts a provider.

Semantic mode may use a configured local or approved provider only when
explicitly requested.

Before sending target content to a provider:

1. confirm provider authorization;
2. apply repository data-handling policy;
3. remove unrelated secrets;
4. record which files or excerpts leave the machine;
5. do not send credentials or private keys;
6. do not treat provider output as deterministic evidence.

If these conditions cannot be met, remain in static mode and perform local
manual review.

## Documentation-context suppression

A keyword detector applied to prose reports every document that discusses an
attack, including this skill's own policy and any other security skill. The
deterministic engine therefore reclassifies a match as documentation context
when one of the following holds:

- the match lies inside a module-level detector constant in Python source;
- the match lies inside a fenced block whose language is not executable;
- the enclosing clause is a negation, such as "a skill cannot:" or
  "does not modify the Trust Registry";
- the line is a negated declaration, such as `write-registry: false`;
- the list lead-in or section heading frames the match as an example.

Three properties keep this from becoming an evasion path:

1. **Nothing is dropped.** Every suppressed match appears in the report under
   `Documentation-context matches` and in `documentationMatches` in the JSON,
   with the reason. Review the suppression itself for an untrusted target.
2. **Prose markers never suppress code.** A file with an executable extension
   is never suppressed by a comment claiming the payload is an example.
3. **A payload cannot exonerate itself.** The matched text is masked out of the
   clause before the negation test, and an inline framing such as
   "For example, <payload>" does not count — only a separate lead-in line or
   section heading does, which a single injected line cannot forge.

## URL classification

An occurrence is `runtime` when it is:

- in a file with an executable extension;
- on a line that also contains a network call;
- inside a fenced block whose language is executable;
- a value in a structured configuration file.

It is `documentation` when it is:

- prose in a Markdown or text file;
- the value of a specification key such as `$schema` or `$id`, on that line or
  the line below it.

Only a runtime occurrence requires a declaration in `external-resources.json`.
A documentation occurrence is a Tier 0 candidate and produces at most a Minor
concern. A documentation URL on a reserved or single-label host — `.invalid`,
`.example`, `.test`, `.localhost`, `example.com`, or a host with no dot — is a
placeholder and produces no finding at all.
