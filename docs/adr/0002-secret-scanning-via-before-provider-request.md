# 0002 Secret scanning via before_provider_request

Secret detection scans the provider request payload via `before_provider_request` rather than overriding built-in tools (`read`, `bash`). The scan is provider-agnostic: it recursively walks all string values in the payload and runs regex matching, ignoring message structure differences between Anthropic, OpenAI, Google, and other providers. Only the request is scanned — the response is not, because correct input-side redaction prevents secrets from reaching the model.

## Considered options

- **Tool overrides:** Override built-in `read` and `bash` tools with wrappers that scan output before it enters context. Rejected because overrides must match the exact result shape of built-in tools (e.g., `ReadToolDetails`, `BashToolDetails`). When pi updates and changes these internal shapes, overrides silently break. Tool overrides are still used for Guards that need to *block* execution, but not for scanning.

- **after_provider_response scanning:** Scan the LLM response for secrets as a second layer. Rejected because it adds latency on every turn and is unnecessary — if input-side redaction works correctly, the model never sees secrets and cannot repeat them.

- **before_provider_request scanning (chosen):** The provider API format (Anthropic Messages API, OpenAI Chat API) is a documented, versioned API that changes far less frequently than pi's internal tool detail types. Scanning all text strings in the payload is provider-agnostic. The payload can be modified and returned.

## Consequences

- Secret scanning survives pi updates unless the provider event API itself changes (low risk).
- The scan runs once per turn on the full payload, not per-tool. This means growing context is re-scanned each turn — acceptable cost for correctness.
- Provider-agnostic scanning means no per-provider code paths to maintain.
