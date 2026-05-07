# Pi Secured Setup

A distributable pi-agent extension package providing multi-layer security: guards that block dangerous actions, scanners that detect risks, and an audit trail that records everything.

## Language

**Guard**:
A module that can block a tool call before execution via the `tool_call` event. Guards have an enforce-and-log posture.
_Avoid_: Protector, filter, interceptor

**Scanner**:
A module that observes data without blocking tool execution. Scanners detect, report, and transform — but never prevent a tool from running.
_Avoid_: Detector, monitor, checker

**Boundary**:
The directory from which pi was launched (`cwd`). File operations via `read`, `write`, and `edit` tools are evaluated relative to this root. Bash commands are not subject to boundary enforcement — they are governed by command classification instead. The boundary is never inferred by walking up the filesystem.
_Avoid_: Project root, project scope, workspace

**Protected path**:
A file pattern (glob) identifying sensitive files that require elevated permission to access. Protected paths are matched against tool call targets.
_Avoid_: Sensitive file, restricted file, blocked file

**Skill approval**:
A recorded decision (with cryptographic hash) that a specific skill is trusted. Only the `SKILL.md` file is hashed — it is the sole file that enters the LLM context. Supporting scripts are protected by the bash Guard. Approvals are stored in `skill-approvals.json` and verified on every session start. New or changed skills prompt for approval once; subsequent sessions show a notification only. Re-trigger with `/security:skills`.
_Avoid_: Skill validation, skill verification, skill allowlist

**Audit event**:
A single append-only JSONL record of a security-relevant action: blocks, confirmations, redactions, skill changes. The log rotates automatically based on configurable thresholds (default: 10MB per file, 3 files retained).
_Avoid_: Log entry, security log, event

**Secret**:
A credential value (API key, password, token, private key, connection string) that must not reach the LLM context in plaintext. Redacted values are replaced with `***REDACTED:{pattern-name}***` so the agent retains type information without the value.
_Avoid_: Credential, sensitive data, key (ambiguous with cryptographic key)

**Config layer**:
One of three configuration sources, merged in priority order: defaults (shipped with package), machine (`~/.pi/agent/security/`), project (`.pi/security/`). All configurable files (`protected-paths.json`, `command-rules.json`, `allowed-external.json`) can exist at any layer. Later layers add patterns with a `!` prefix to exclude inherited patterns from earlier layers.
_Avoid_: Config level, config source, config tier

**Command classification**:
The assignment of a bash command to one of four categories: SAFE, MODERATE, DANGEROUS, or EXTERNAL. SAFE and MODERATE are severity levels. DANGEROUS covers destructive operations. EXTERNAL covers any command that sends data outside the machine, regardless of severity.
_Avoid_: Risk level, threat level, command rating

## Relationships

- A **Guard** operates on tool calls *before* execution via a single combined `tool_call` handler. A **Scanner** operates on tool results or provider payloads *after* execution.
- **Guard pipeline** evaluates checks in fixed order: boundary → protected-paths → bash-gate. First block wins. No short-circuit past a confirmation.
- Secret scanning is provider-agnostic: the Scanner recursively walks the provider payload for all string values and runs regex matching, ignoring message structure differences between Anthropic, OpenAI, Google, etc.
- **Boundary** defines the geographic limit for Guards. **Protected paths** define the logical limit within that boundary.
- **Command classification** determines how the bash Guard responds to a given command.
- **Secret** scanning is performed by a Scanner that redacts values in the provider payload.
- **Skill approval** is managed by a Scanner that detects changes and prompts for decisions.
- Every Guard and Scanner action produces an **Audit event**.
- **Config layers** are merged to produce the runtime configuration for all Guards and Scanners. Pattern lists are additive; a `!` prefix on a pattern in a later layer excludes the matching inherited pattern.

## Example dialogue

> **Dev:** "Can the skill module block a malicious skill from loading?"
> **Domain expert:** "No — the skill module is a Scanner. It detects changes, shows diffs, and prompts for approval, but it cannot prevent pi from loading a skill file. Only Guards can block actions."

> **Dev:** "What's the difference between boundary enforcement and protected paths?"
> **Domain expert:** "Boundary is geographic — 'is this file inside cwd?' Protected paths are logical — 'even though this file IS inside cwd, is it sensitive?' Boundary is checked first, then protected paths."

> **Dev:** "If a secret appears in a bash output, what happens?"
> **Domain expert:** "The bash Guard classifies the command and may block or confirm it. But if the command runs and the output contains a Secret, the secret Scanner redacts it from the provider payload before it reaches the LLM. The scan is provider-agnostic — it walks all text strings in the payload regardless of message format."

> **Dev:** "What happens when I switch models from Anthropic to OpenAI?"
> **Domain expert:** "Nothing changes for the Scanner. It doesn't parse message structure — it just finds string values and runs regex. Provider switching is transparent."

## Design constraints

- All three Guard modules (boundary, protected-paths, bash-gate) are evaluated by a single `tool_call` handler. They export pure evaluation functions, not independent event registrations. This ensures deterministic ordering and prevents multiple confirmation dialogs for a single tool call.
- Skill approval prompts fire once per skill change. Subsequent sessions display a notification for unapproved skills without blocking. Use `/security:skills` to re-trigger the approval flow.
- The `/security` command is a dashboard for visibility. `/security:trust <skill>` and `/security:allow <path>` are convenience commands that persist config changes and auto-reload. No session-scoped overrides exist — all changes are persistent.

## Flagged ambiguities

- "Block" vs "confirm" — resolved: **block** means the action is rejected with no option to proceed in that tool call. **Confirm** means a dialog is shown and the user can choose to proceed.
- "NETWORK" was renamed to **EXTERNAL** — resolved: the concern is data leaving the machine, not networking per se. EXTERNAL better captures commands like `aws`, `gcloud`, `docker push` that may not use raw network sockets but send data externally.
- "Skill verification" was used ambiguously to mean both hash-checking and approval — resolved: **skill approval** is the human decision; **hash verification** is the mechanical integrity check.
