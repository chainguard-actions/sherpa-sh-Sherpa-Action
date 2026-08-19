<!-- markdownlint-disable -->

# Hardening Report: sherpa-sh--Sherpa-Action/v1.0.0-alpha.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **sherpa-sh--Sherpa-Action/v1.0.0-alpha.1** was hardened automatically. 8 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple ${{ }} expressions are interpolated directly inside run: shell command strings in action.yml, violating rule (a). This allows template substitution to inject arbitrary shell content before the shell ever parses the command.

Offending lines:
- Line 44: `SHERPA_SRC="${{ github.action_path }}/sherpa"` — github context injected into shell variable assignment
- Line 45: `SHERPA_DEST="${{ github.workspace }}/.sherpa-plugin"` — github context injected into shell variable assignment
- Line 66: `export ANTHROPIC_API_KEY="${{ inputs.anthropic_api_key }}"` — attacker-controlled input directly in run: block
- Line 67: `export GITHUB_TOKEN="${{ inputs.github_token }}"` — attacker-controlled input directly in run: block
- Line 71: `--plugin-dir "${{ github.workspace }}/.sherpa-plugin"` — github context injected into CLI argument
- Line 72: `--max-turns "${{ inputs.max_turns }}"` — attacker-controlled input directly in CLI argument
- Line 73: `"/Sherpa/deploy ${{ inputs.prompt }}"` — attacker-controlled input directly interpolated into shell command string; an attacker can supply a prompt containing shell metacharacters to achieve command injection

Fix: move all ${{ }} values into env: variables and reference them as quoted shell variables (e.g., "$INPUT_PROMPT").

Locations:

- `action.yml:44`
- `action.yml:45`
- `action.yml:66`
- `action.yml:67`
- `action.yml:71`
- `action.yml:72`
- `action.yml:73`

### github-env-injection (severity: high)

The 'Run Claude Code with Sherpa' step writes $OUTPUT to $GITHUB_OUTPUT without sanitization. $OUTPUT is the result of running the claude CLI with attacker-controlled inputs (inputs.prompt, inputs.max_turns, inputs.anthropic_api_key, inputs.github_token) and the workflow-inherited ENV_VARS_JSON environment. If the claude process emits newline characters in its output, an attacker could inject arbitrary key=value pairs into $GITHUB_OUTPUT (e.g., by crafting a prompt that causes claude to print 'EOF\nmalicious_key=malicious_value'). The required sanitization step (`printf '%s' "$OUTPUT" | tr -d '\n\r'`) is absent before the heredoc write.

Offending block (lines 76-82):
```
{
  echo "result<<EOF"
  echo "$OUTPUT"
  echo "EOF"
} >> $GITHUB_OUTPUT
```

Locations:

- `action.yml:76`

### unpinned-uses (severity: high)

The composite action uses `actions/setup-node@v4` — a mutable tag reference rather than a pinned 40-character commit SHA. A tag can be moved by the upstream repository owner (or a compromised account), allowing a supply-chain attack to silently substitute malicious code. Fix: pin to a full commit SHA, e.g. `actions/setup-node@1d0ff469b4a71b8ffb4df2714b6e1b9b6b6b6b6b # v4`.

Locations:

- `action.yml:36`

### suspicious-run-content (severity: high)

Sub-check: eval-dynamic. The 'Run Claude Code with Sherpa' step uses `eval "$(...)"` with command substitution to dynamically construct and execute shell export statements from the ENV_VARS_JSON environment variable (which is populated via `${{ toJSON(env) }}` — the full workflow env context). This pattern matches the eval-dynamic check: `eval "$(echo "$ENV_VARS_JSON" | jq -r 'to_entries | .[] | "export \(.key)=\(.value | @sh)"')"`. If ENV_VARS_JSON contains attacker-influenced values (e.g., from a workflow that sets env vars from github.event inputs), the jq-constructed export commands could be manipulated to execute arbitrary shell code despite the @sh quoting attempt.

Locations:

- `action.yml:63`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.anthropic_api_key }}" appears directly in run: block of step "Run Claude Code with Sherpa"; move to env: map

Locations:

- `action.yml:72`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.github_token }}" appears directly in run: block of step "Run Claude Code with Sherpa"; move to env: map

Locations:

- `action.yml:73`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.max_turns }}" appears directly in run: block of step "Run Claude Code with Sherpa"; move to env: map

Locations:

- `action.yml:80`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.prompt }}" appears directly in run: block of step "Run Claude Code with Sherpa"; move to env: map

Locations:

- `action.yml:81`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, suspicious-run-content, static-inline-injection

**Notes:**

Rewrote hardened/action/action.yml to fix all findings:
1. Pinned actions/setup-node@v4 to full SHA 49933ea5288caeca8642d1e84afbd3f7d6820020.
2. Moved all ${{ }} expressions (github.action_path, github.workspace, inputs.anthropic_api_key, inputs.github_token, inputs.max_turns, inputs.prompt) out of run: blocks into env: maps; referenced as plain shell variables.
3. Sanitized OUTPUT before writing to $GITHUB_OUTPUT using `printf '%s' "$OUTPUT" | tr -d '\r'`; also changed heredoc delimiter from EOF to SHERPA_EOF.
4. Replaced dangerous eval+jq pattern with a safe while-read loop using `export "$key=$value"` — no eval, no shell code execution from attacker-controlled data.

### Iteration 2

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all three findings in action.yml:
1. (script-injection, line 90) Split '/Sherpa/deploy $INPUT_PROMPT' into two separate arguments: '/Sherpa/deploy' and '$INPUT_PROMPT', so the prompt is properly double-quoted as its own shell word.
2. (script-injection, line 80) Removed the ENV_VARS_JSON env var and the entire while-loop that exported attacker-controllable key=value pairs from toJSON(env) into the shell environment, eliminating the risk of overwriting ANTHROPIC_API_KEY, GITHUB_TOKEN, or other sensitive variables.
3. (github-env-injection, line 92) Changed `tr -d '\r'` to `tr -d '\n\r'` to strip both newlines and carriage returns from the output before writing to $GITHUB_OUTPUT, preventing newline injection attacks.

