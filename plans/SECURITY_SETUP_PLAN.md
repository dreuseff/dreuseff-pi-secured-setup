# Pi-Agent Secured Setup — Implementation Plan

## Overview

A distributable pi-agent extension that provides multi-layer security: **Guards** that block dangerous actions, **Scanners** that detect risks, and an **audit trail** that records everything. Installed on any machine with a single `pi install` command.

See [CONTEXT.md](../CONTEXT.md) for domain terminology and [docs/adr/](../docs/adr/) for architectural decisions.

---

## Threat Model

| Threat | Severity | Mitigation |
|--------|----------|------------|
| **Accidental cross-project damage** | High | Project boundary enforcement (Guards) |
| **Sensitive file exposure** | High | Protected paths (Guards) + secret detection (Scanner) |
| **Destructive commands** | High | Bash command classification (Guard) |
| **Supply chain (skills)** | Medium | SKILL.md hash verification + change alerts (Scanner) |
| **Data exfiltration** | Medium | EXTERNAL command detection + secret redaction |
| **No accountability** | Medium | Append-only audit log |

---

## Decisions Record

| # | Decision | Choice | ADR |
|---|----------|--------|-----|
| 1 | Threat model | Accidental damage + Supply chain + Audit | — |
| 2 | Risk scope | Wrong-project + Sensitive-files + Blast-radius | — |
| 3 | Project boundary | Read outside → confirm, Write/Edit outside → block; **no boundary for bash** | [ADR-0003](../docs/adr/0003-no-boundary-enforcement-for-bash.md) |
| 4 | Protected paths | Global defaults + machine + project overrides, `!` exclusion syntax | — |
| 5 | Bash gating | SAFE / MODERATE / DANGEROUS / EXTERNAL (not NETWORK) | — |
| 6 | Skill security | Hash verification (SKILL.md only) + detect + warn (no blocking) | [ADR-0004](../docs/adr/0004-skill-integrity-hashes-only-skill-md.md) |
| 7 | Skill install guard | Detect + warn at pi startup, no quarantine | — |
| 8 | Skill integrity DB | Own `skill-approvals.json` (`.skill-lock.json` is not a standard) | — |
| 9 | Audit log | JSONL file + `/security` dashboard + configurable rotation | — |
| 10 | Project root | `cwd` — explicit boundary, no walking up | — |
| 11 | Distribution | Git-based pi package | — |
| 12 | Code structure | One entry point, internally modular, **single combined guard handler** | [ADR-0001](../docs/adr/0001-single-combined-guard-handler.md) |
| 13 | Emergency bypass | No bypass — edit config + `/reload` | — |
| 14 | Skill blocking | Detect + warn only | — |
| 15 | Secret detection mechanism | `before_provider_request` payload scan (provider-agnostic) | [ADR-0002](../docs/adr/0002-secret-scanning-via-before-provider-request.md) |
| 16 | Secret detection action | Redact silently as `***REDACTED:{pattern-name}***` + audit + notification | — |
| 17 | Skill approval prompting | Prompt once per change, then notification only; `/security:skills` to re-trigger | — |
| 18 | Config layer merging | Additive with `!` exclusion; all config files can exist at any layer | — |
| 19 | `/security` admin commands | `/security:trust <skill>` and `/security:allow <path>` persist config + auto-reload | — |
| 20 | Response scanning | No — only scan provider request; input-side redaction prevents leaks | — |

---

## Package Structure

```
pi-secured-setup/
├── package.json                    # Pi package manifest
├── README.md                       # Installation & usage docs
├── CONTEXT.md                      # Domain terminology
├── docs/adr/                       # Architectural decision records
│   ├── 0001-single-combined-guard-handler.md
│   ├── 0002-secret-scanning-via-before-provider-request.md
│   ├── 0003-no-boundary-enforcement-for-bash.md
│   └── 0004-skill-integrity-hashes-only-skill-md.md
├── plans/
│   └── SECURITY_SETUP_PLAN.md      # This file
├── extensions/
│   └── security.ts                 # Entry point: single guard handler + scanner registrations
├── lib/
│   ├── config.ts                   # Config loading: defaults → machine → project (with ! exclusion)
│   ├── guard-pipeline.ts           # Combined guard handler (boundary → protected-paths → bash-gate)
│   ├── boundary.ts                 # Pure function: evaluateBoundary(toolCall) → verdict
│   ├── protected-paths.ts          # Pure function: evaluateProtectedPaths(toolCall) → verdict
│   ├── bash-gate.ts                # Pure function: classifyCommand(command) → verdict
│   ├── secret-scanner.ts           # Scanner: before_provider_request payload scan
│   ├── skill-scanner.ts            # Scanner: SKILL.md hash verification + change detection
│   ├── audit.ts                    # Append-only JSONL audit log + /security commands
│   └── utils.ts                    # Shared helpers (hashing, path resolution, etc.)
└── defaults/
    ├── protected-paths.json        # Default global protected patterns
    └── command-rules.json          # Default command classification rules
```

### Runtime config locations (never touched by updates)

```
~/.pi/agent/security/               # Machine-specific config
├── protected-paths.json            # Local overrides (merge with defaults, supports ! exclusion)
├── command-rules.json              # Local overrides (merge with defaults, supports ! exclusion)
├── allowed-external.json           # External paths allowed for this machine
├── skill-approvals.json            # Auto-managed: skill hash + approval decisions
├── audit.jsonl                     # Append-only audit log
└── audit-config.json               # Rotation settings (maxFileSize, maxFiles)

.pi/security/                       # Per-project config (in project root = cwd)
├── protected-paths.json            # Project-specific patterns (supports ! exclusion)
├── command-rules.json              # Project-specific command overrides
└── allowed-external.json           # External paths this project can access
```

---

## Module Specifications

### 1. Config Loader (`lib/config.ts`)

**Responsibility:** Load and merge configuration from three layers.

**Resolution order (later layers add to or exclude from earlier):**
1. `defaults/` — shipped with the package
2. `~/.pi/agent/security/` — machine-specific
3. `.pi/security/` — project-specific (relative to cwd)

**Merge rules:**
- Pattern lists are **additive** — each layer can add new patterns
- A `!` prefix **excludes** an inherited pattern from an earlier layer (e.g., `!"*secret*"` removes the `*secret*` pattern)
- All configurable files (`protected-paths.json`, `command-rules.json`, `allowed-external.json`) can exist at any layer
- Non-pattern fields (e.g., `writeAction`, `readAction`) in later layers replace earlier values

**Config shapes:**

```typescript
// protected-paths.json
{
  "patterns": [
    ".env",
    ".env.*",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "*secret*",
    "*credential*",
    "*token*.json"
  ],
  "writeAction": "block",        // "block" | "confirm"
  "readAction": "confirm"         // "block" | "confirm" | "allow"
}

// command-rules.json — categories are SAFE, MODERATE, DANGEROUS, EXTERNAL
{
  "safe": [
    "^ls\\b", "^cat\\b", "^head\\b", "^tail\\b", "^grep\\b", "^rg\\b",
    "^find\\b", "^fd\\b", "^git status\\b", "^git diff\\b", "^git log\\b",
    "^git branch\\b", "^wc\\b", "^file\\b", "^which\\b", "^echo\\b",
    "^pwd\\b", "^whoami\\b", "^date\\b", "^uname\\b"
  ],
  "moderate": [
    "^mkdir\\b", "^touch\\b", "^cp\\b", "^mv\\b", "^chmod\\b",
    "^npm\\b", "^npx\\b", "^pip\\b", "^cargo\\b", "^go\\b",
    "^git add\\b", "^git commit\\b", "^git checkout\\b", "^git stash\\b",
    "^git merge\\b", "^git rebase\\b"
  ],
  "dangerous": [
    "rm\\s+(-rf?|--recursive)", "sudo\\b", "git push\\s+--force",
    "git push\\s+-f\\b", "DROP\\b", "TRUNCATE\\b",
    "(chmod|chown)\\b.*777", "\\beval\\b", "\\bexec\\b",
    "dd\\s+if=", ">\\s*/dev/sd", "mkfs\\b", "fdisk\\b"
  ],
  "external": [
    "\\bcurl\\b", "\\bwget\\b", "\\bnc\\b", "\\bncat\\b",
    "\\bssh\\b", "\\bscp\\b", "\\brsync\\b", "\\btelnet\\b",
    "\\bdocker\\s+push\\b", "\\bdocker\\s+pull\\b",
    "\\bgcloud\\b", "\\baws\\b", "\\baz\\b"
  ]
}

// allowed-external.json
{
  "paths": [
    "~/.agents/skills",
    "/tmp"
  ]
}

// audit-config.json (machine only)
{
  "maxFileSize": 10485760,   // 10MB
  "maxFiles": 3
}
```

---

### 2. Guard Pipeline (`lib/guard-pipeline.ts`) — the single combined handler

> **See [ADR-0001](../docs/adr/0001-single-combined-guard-handler.md) for the rationale.**

**Mechanism:** Registers a single `tool_call` event handler that orchestrates all three Guard modules.

**Each Guard module exports a pure evaluation function:**

```typescript
// boundary.ts
evaluateBoundary(toolName: string, input: Record<string, unknown>, config: Config): GuardVerdict

// protected-paths.ts
evaluateProtectedPaths(toolName: string, input: Record<string, unknown>, config: Config): GuardVerdict

// bash-gate.ts
classifyCommand(command: string, config: Config): GuardVerdict
```

**`GuardVerdict` type:**

```typescript
type GuardVerdict =
  | { action: "allow" }
  | { action: "block"; reason: string }
  | { action: "confirm"; message: string };
```

**Pipeline logic:**

```
On tool_call event:
  1. evaluateBoundary()
     → block: return block, skip remaining checks
     → confirm: show dialog; if denied, return block
     → allow: continue to next check

  2. evaluateProtectedPaths()
     → block: return block, skip remaining checks
     → confirm: show dialog; if denied, return block
     → allow: continue to next check

  3. classifyCommand() — only for bash tool
     → confirm: show dialog; if denied, return block
     → allow: pass through

  Log verdict to audit
  Return final verdict to pi
```

---

### 3. Boundary (`lib/boundary.ts`)

> **See [ADR-0003](../docs/adr/0003-no-boundary-enforcement-for-bash.md) for why bash is excluded.**

**Pure function:** `evaluateBoundary(toolName, input, config) → GuardVerdict`

**Applies to tools:** `read`, `write`, `edit` only. **Not `bash`.**

**Logic:**

```
If toolName is "bash" → return allow (not our concern)

Resolve target path from tool parameters
If path is inside cwd → return allow

If path is outside cwd:
  Check merged allowed-external.json → if listed, return allow

  If tool is "write" or "edit" → return block
  If tool is "read" → return confirm
```

---

### 4. Protected Paths (`lib/protected-paths.ts`)

**Pure function:** `evaluateProtectedPaths(toolName, input, config) → GuardVerdict`

**Applies to tools:** `read`, `write`, `edit`. **Not `bash`.**

**Logic:**

```
If toolName is "bash" → return allow

Resolve target path from tool parameters
Match against merged protected patterns (defaults + machine + project, with ! exclusions applied)

If no match → return allow

If match:
  If tool is "write" or "edit" → return block
  If tool is "read" → return confirm
```

---

### 5. Bash Gate (`lib/bash-gate.ts`)

**Pure function:** `classifyCommand(command, config) → GuardVerdict`

**Applies to tool:** `bash` only.

**Logic:**

```
If toolName is not "bash" → return allow

Extract command string from tool parameters
Match against merged classification rules (defaults + machine + project, with ! exclusions applied)

Priority (first match wins):
  1. DANGEROUS pattern → return confirm
  2. EXTERNAL pattern → return confirm
  3. MODERATE pattern → return allow (logged as moderate)
  4. SAFE pattern → return allow (logged as safe)
  5. No match (unknown command) → return confirm
```

**Command analysis notes:**
- Match against the full command string (including pipes and subshells)
- If command contains pipes `|`, classify based on the **most dangerous** component
- Subshells `$(...)` are extracted and classified independently
- Commands starting with `!` or `!!` (pi inline bash) are handled by pi before reaching the extension

---

### 6. Secret Scanner (`lib/secret-scanner.ts`)

> **See [ADR-0002](../docs/adr/0002-secret-scanning-via-before-provider-request.md) for the rationale.**

**Mechanism:** `before_provider_request` event handler.

**Scan approach:** Provider-agnostic. Recursively walk the entire payload for string values, run regex matching, and perform string replacement. No parsing of provider-specific message structures.

**Only scans the request** — not the response. Input-side redaction prevents secrets from reaching the model, so they cannot appear in responses.

**Logic:**

```
On before_provider_request:
  Recursively walk payload object
  For every string value found:
    Run against secret patterns (with false-positive filtering)
    If match:
      Replace with ***REDACTED:{pattern-name}***
      Record to redaction list for this turn
  
  If any redactions made:
    Log each to audit: { type, patternName, tool context }
    Set notification flag
  
  Return modified payload

On after_provider_response:
  If notification flag is set:
    Show notification: "⚠️ N secret(s) redacted from context this turn"
```

**Secret patterns:**

```typescript
const SECRET_PATTERNS = [
  // Cloud provider keys
  { name: "aws-access-key", pattern: /AKIA[0-9A-Z]{16}/g },
  { name: "aws-secret-key", pattern: /(?<=aws_secret_access_key\s*=\s*|AWS_SECRET_ACCESS_KEY\s*=\s*)[A-Za-z0-9/+=]{40}/g },

  // LLM provider keys
  { name: "anthropic-key", pattern: /sk-ant-api[a-zA-Z0-9_-]{20,}/g },
  { name: "openai-key", pattern: /sk-[a-zA-Z0-9]{20,}/g },
  { name: "gemini-key", pattern: /AIza[a-zA-Z0-9_-]{35}/g },

  // Generic secrets
  { name: "private-key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { name: "api-key-generic", pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}/gi },
  { name: "bearer-token", pattern: /(?:bearer|authorization)\s*[:=]\s*["']?[A-Za-z0-9_.-]{20,}/gi },
  { name: "password", pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/gi },

  // Database connection strings
  { name: "db-connection", pattern: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s"']+/gi },

  // GitHub tokens
  { name: "github-token", pattern: /gh[ps]_[a-zA-Z0-9]{36}/g },
  { name: "github-pat", pattern: /ghp_[a-zA-Z0-9]{36}/g },

  // Slack, Discord, etc.
  { name: "slack-token", pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g },
  { name: "discord-token", pattern: /[\w-]{24}\.[\w-]{6}\.[\w-]{27}/g },

  // High entropy detection (fallback)
  { name: "high-entropy", pattern: /(?:key|token|secret|password|credential)["']?\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{32,})["']?/gi },
];
```

**False positive mitigation:**
- Skip patterns that are clearly placeholders: `YOUR_...`, `<...>`, `xxx...`, `***`, `REPLACE_...`
- Skip `.example`, `.sample`, `.template` file contents
- Skip lines that are comments (start with `#`, `//`, `--`)

**Redaction format:** `***REDACTED:{pattern-name}***` — the agent retains the type of secret without the value, enabling it to reason about configuration without accessing credentials.

---

### 7. Skill Scanner (`lib/skill-scanner.ts`)

> **See [ADR-0004](../docs/adr/0004-skill-integrity-hashes-only-skill-md.md) for why only SKILL.md is hashed.**

**Mechanism:** `session_start` event handler.

**What is scanned:** Only `SKILL.md` files. Supporting scripts and assets are not hashed — the bash Guard covers script execution.

**Approval behavior:** Prompt once per skill change. Subsequent sessions show a notification for unapproved skills without blocking. Re-trigger the approval flow with `/security:skills`.

**Logic:**

```
On session_start:
  Scan all skill directories:
    ~/.pi/agent/skills/
    ~/.agents/skills/
    .pi/skills/
    .agents/skills/ (in cwd + ancestors)

  For each discovered skill:
    Hash SKILL.md (sha256)
    Compare against skill-approvals.json:
      New skill (no entry) → queue alert
      Changed hash → queue alert with diff
      Approved match → silent
      Previously skipped/unapproved → show notification only (no prompt)

  If any new/changed alerts queued:
    For each alert:
      Show skill name, source directory, and what changed
      If new: show full SKILL.md content
      If changed: show diff of SKILL.md
      Ask: "Approve this skill? (yes / no / skip)"
    Update skill-approvals.json with decisions
    Log all changes to audit
  Else if any unapproved skills exist:
    Show notification: "⚠️ N unapproved skill(s). Use /security:skills to review."
```

**`skill-approvals.json` format:**

```json
{
  "version": 1,
  "skills": {
    "grill-me": {
      "path": "/home/user/.agents/skills/grill-me",
      "hash": "sha256:abc123...",
      "approvedAt": "2026-05-06T10:30:00Z",
      "source": "~/.agents/skills/"
    }
  }
}
```

---

### 8. Audit Logger (`lib/audit.ts`)

**Mechanism:** Shared utility used by all modules. Registers `/security` commands.

**Audit entry format (JSONL):**

```json
{
  "timestamp": "2026-05-06T10:30:00.123Z",
  "sessionId": "abc123",
  "type": "boundary.block",
  "severity": "warning",
  "details": {
    "tool": "write",
    "path": "/home/user/other-project/file.ts",
    "boundary": "/home/user/project-a",
    "reason": "write outside project boundary"
  }
}
```

**Event types:**

| Type | Severity | Description |
|------|----------|-------------|
| `boundary.confirm` | info | User confirmed read outside project |
| `boundary.block` | warning | Write blocked outside project |
| `protected.confirm` | info | User confirmed read of protected file |
| `protected.block` | warning | Write to protected file blocked |
| `bash.safe` | debug | Safe command auto-approved |
| `bash.moderate` | info | Moderate command executed |
| `bash.dangerous.confirm` | warning | User confirmed dangerous command |
| `bash.dangerous.block` | warning | Dangerous command blocked |
| `bash.external.confirm` | warning | User confirmed external command |
| `bash.external.block` | warning | External command blocked |
| `bash.unknown.confirm` | warning | User confirmed unknown command |
| `secret.redacted` | warning | Secret detected and redacted |
| `skill.new` | warning | New skill detected |
| `skill.changed` | warning | SKILL.md content changed |
| `skill.approved` | info | Skill approved by user |
| `skill.denied` | warning | Skill not approved |

**Log rotation:** Configurable via `~/.pi/agent/security/audit-config.json` (default: 10MB per file, 3 files retained).

**Commands:**

| Command | Description |
|---------|-------------|
| `/security` | Dashboard: blocked/confirmed counts, recent events, skill status |
| `/security:skills` | Re-trigger skill approval flow for all pending/unapproved |
| `/security:trust <skill>` | Approve a skill by name, persist to config, auto-reload |
| `/security:allow <path>` | Add external path to allowed-external.json, auto-reload |
| `/security:clean` | Trim audit log (remove entries older than N days) |

**`/security` dashboard output:**

```
🔒 Security Dashboard — Session abc123

This session:
  🔴 Blocked:    3 actions
  🟡 Confirmed:  5 actions
  🔵 Auto-approved: 42 actions
  ⚠️ Secrets redacted: 2

Recent events:
  10:28 [BLOCKED] write → /home/user/other-project/file.ts (outside boundary)
  10:25 [CONFIRMED] bash → curl https://api.example.com (external)
  10:22 [REDACTED] secret (anthropic-key) in read → .env

Skill status:
  ✅ 18 approved, ⚠️ 0 pending, 🚫 0 denied
```

---

## Entry Point (`extensions/security.ts`)

```typescript
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { loadConfig } from "../lib/config.js";
import { registerGuardPipeline } from "../lib/guard-pipeline.js";
import { evaluateBoundary } from "../lib/boundary.js";
import { evaluateProtectedPaths } from "../lib/protected-paths.js";
import { classifyCommand } from "../lib/bash-gate.js";
import { registerSecretScanner } from "../lib/secret-scanner.js";
import { registerSkillScanner } from "../lib/skill-scanner.js";
import { registerAuditCommand, auditLog } from "../lib/audit.js";

export default function (pi: ExtensionAPI) {
  const config = loadConfig();

  registerAuditCommand(pi, config);

  // Single combined guard handler (ADR-0001)
  registerGuardPipeline(pi, config, auditLog, {
    evaluateBoundary,
    evaluateProtectedPaths,
    classifyCommand,
  });

  // Scanners (observe, don't block)
  registerSecretScanner(pi, config, auditLog);
  registerSkillScanner(pi, config, auditLog);
}
```

---

## `package.json`

```json
{
  "name": "pi-secured-setup",
  "version": "1.0.0",
  "description": "Security extension for pi-agent: boundary enforcement, secret detection, skill verification, and audit logging",
  "keywords": ["pi-package"],
  "pi": {
    "extensions": ["extensions"]
  },
  "peerDependencies": {
    "@mariozechner/pi-coding-agent": "*",
    "@mariozechner/pi-ai": "*",
    "@mariozechner/pi-tui": "*",
    "typebox": "*"
  }
}
```

---

## Installation & Updates

```bash
# Install
pi install git:github.com/mwolff44/pi-secured-setup

# Update (pulls latest from git, never touches local config)
pi update pi-secured-setup

# Pin to a version
pi install git:github.com/mwolff44/pi-secured-setup@v1.0.0
```

**First-run experience:**
1. Extension loads → detects no `~/.pi/agent/security/` directory
2. Creates directory with default configs
3. Scans all skills → prompts approval for each one (once)
4. Shows: "🔒 Security extension initialized. Defaults written to ~/.pi/agent/security/"

---

## Implementation Phases

### Phase 1: Foundation (MVP)
- [ ] Package structure + `package.json`
- [ ] Config loader (`lib/config.ts`) — three-layer merge with `!` exclusion
- [ ] Audit logger (`lib/audit.ts`) + `/security` command + rotation
- [ ] Entry point (`extensions/security.ts`)

### Phase 2: Guard Pipeline
- [ ] Guard pipeline orchestrator (`lib/guard-pipeline.ts`)
- [ ] Boundary evaluation (`lib/boundary.ts`) — `read`/`write`/`edit` only
- [ ] Protected paths (`lib/protected-paths.ts`) — pattern matching with merge
- [ ] Bash gate (`lib/bash-gate.ts`) — SAFE/MODERATE/DANGEROUS/EXTERNAL

### Phase 3: Scanners
- [ ] Secret scanner (`lib/secret-scanner.ts`) — `before_provider_request`, provider-agnostic
- [ ] Skill scanner (`lib/skill-scanner.ts`) — SKILL.md hash + prompt-once + `/security:skills`

### Phase 4: Admin Commands
- [ ] `/security:trust <skill>` — approve skill from CLI
- [ ] `/security:allow <path>` — add external path from CLI
- [ ] `/security:clean` — trim audit log

### Phase 5: Polish
- [ ] README documentation
- [ ] Default config files (`defaults/`)
- [ ] Per-project config examples
- [ ] Testing across multiple machines

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Pi updates break `tool_call` event API | Low risk — event API is stable; monitor pi changelog |
| Pi updates change provider payload format | Low risk — Scanner is provider-agnostic (walks strings, not structure) — [ADR-0002](../docs/adr/0002-secret-scanning-via-before-provider-request.md) |
| Secret detection false positives | Placeholder/comment detection; notification-only (never blocks) |
| Bash commands escape boundary | By design — bash is governed by classification only, not boundary — [ADR-0003](../docs/adr/0003-no-boundary-enforcement-for-bash.md) |
| Skill guard can't block loading | By design — detect + warn is the agreed approach |
| Skill tampering via non-SKILL.md files | Covered by bash Guard for execution; SKILL.md is the LLM attack surface — [ADR-0004](../docs/adr/0004-skill-integrity-hashes-only-skill-md.md) |
| Config conflicts with other extensions | Single guard handler runs deterministically; all decisions logged |
| Audit log grows unbounded | Configurable rotation (default: 10MB / 3 files) |
| Multiple confirmation dialogs | Prevented by single combined handler — [ADR-0001](../docs/adr/0001-single-combined-guard-handler.md) |
