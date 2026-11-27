# Model Connection Check

## Purpose

Verify that the configured OpenAI-compatible endpoint, API key, and model ID can
complete one short model turn through DeepSeek Harness. This is a connectivity
check, not part of the CVE workflow.

## Where it is used

- Code: `src/kreprolab/__init__.py`, the branch where the `cve` argument is
  omitted.
- Command: `uv run kreprolab` (optionally with `--config <path>`).
- DSH profile: `sdk-minimal`, with tools disabled by `open_harness()`.

## Prompt

```text
Reply with the single word OK.
```

No custom system prompt is set for this check; the profile's default persona is
used.

## Expected behavior

- The result must have `finish_reason == "completed"` and a non-empty
  `final_response`.
- The reply is printed to stdout.
- Configuration, transport, and model errors exit with status 1; the API key is
  redacted from the error message.
