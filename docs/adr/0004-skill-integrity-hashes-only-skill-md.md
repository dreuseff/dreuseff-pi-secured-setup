# 0004 Skill integrity checks hash only SKILL.md

The skill Scanner hashes only the `SKILL.md` file when verifying skill integrity. Supporting files (scripts, assets, references) are not hashed.

## Considered options

- **Hash all files recursively:** Maximum coverage — any change to any file in the skill directory triggers an alert. Rejected because skill directories can contain generated files, `node_modules`, or large assets that change frequently without affecting security. Rehashing on every session start is slow for large skills.

- **Hash SKILL.md + referenced files:** Parse the SKILL.md markdown for relative file references and hash those too. Rejected because it requires markdown link parsing, which is fragile. The benefit (catching script tampering) is already covered by the bash Guard, which gates command execution.

- **Hash only SKILL.md (chosen):** SKILL.md is the sole file that enters the LLM context via pi's progressive disclosure system. It is the attack surface — a tampered SKILL.md can instruct the model to perform malicious actions. Supporting scripts are only executed when the agent explicitly runs them via `bash`, which is subject to command classification.

## Consequences

- If an attacker modifies a skill's `scripts/helper.sh` without touching `SKILL.md`, the Scanner won't detect it. The bash Guard is the defense layer for script execution.
- Hash verification is fast — one file per skill, checked on session start.
- Skill directories can freely update assets, dependencies, or generated files without triggering approval prompts.
