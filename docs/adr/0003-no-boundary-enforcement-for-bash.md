# 0003 No boundary enforcement for bash commands

Boundary enforcement applies only to `read`, `write`, and `edit` tools — not to the `bash` tool. Bash commands are governed exclusively by command classification (SAFE, MODERATE, DANGEROUS, EXTERNAL).

## Considered options

- **Best-effort path extraction from bash commands:** Parse the command string for file paths (`/`, `~/`, `../`), resolve them, and apply boundary rules. Rejected because bash command parsing is unreliable — paths appear inside variables (`$FOO`), flags (`-c "..."`), subshells (`$(...)`), and pipes. False positives create noisy confirmation dialogs; false negatives create a false sense of security.

- **Default to outside-boundary when path extraction fails:** Treat ambiguous commands as outside boundary and require confirmation. Rejected because most bash commands don't contain explicit paths (`npm install`, `git commit`, `python script.py`). This would trigger constant confirmations for benign operations.

- **Skip boundary for bash entirely (chosen):** The `read`, `write`, and `edit` tools have explicit path parameters — boundary enforcement is reliable there. Bash security is handled by command classification, which catches dangerous operations regardless of path.

## Consequences

- A `bash` command like `cat /etc/passwd` will not be caught by boundary enforcement. It would need to be caught by command classification (`cat` is SAFE by default — so it wouldn't be caught at all).
- Users who need path-based security for bash should add specific command patterns to DANGEROUS or EXTERNAL in their command-rules config.
- The boundary concept is clean: it applies where paths are explicit parameters, not where they're buried in command strings.
