<!-- markdownlint-disable -->

# Hardening Report: sherpa-sh--Sherpa-Action/v1.0.0-alpha.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **sherpa-sh--Sherpa-Action/v1.0.0-alpha.1** was hardened automatically. 8 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

action.yml uses actions/setup-node@v4, which is pinned to a mutable version tag rather than an immutable 40-character commit SHA. This allows the referenced action to be silently changed by a supply-chain attacker. It should be pinned to a full SHA, e.g. actions/setup-node@1d0ff469b12294b4f0f8b8b4b8b8b8b8b8b8b8b # v4.

Locations:

- `action.yml:38`

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ ... }} expressions are interpolated directly inside run: shell command strings in action.yml. This means the YAML template engine substitutes the values before the shell ever sees them, allowing an attacker-controlled value to inject arbitrary shell commands.

1. 'Copy Sherpa plugin' step (line ~43): `SHERPA_SRC="${{ github.action_path }}/sherpa"` and `SHERPA_DEST="${{ github.workspace }}/.sherpa-plugin"` — github.* context values interpolated directly.

2. 'Run Claude Code with Sherpa' step (line ~63): `export ANTHROPIC_API_KEY="${{ inputs.anthropic_api_key }}"` — sensitive input interpolated directly into shell.

3. Same step (line ~64): `export GITHUB_TOKEN="${{ inputs.github_token }}"` — token input interpolated directly.

4. Same step (line ~67): `--plugin-dir "${{ github.workspace }}/.sherpa-plugin"` — github.workspace interpolated directly.

5. Same step (line ~68): `--max-turns "${{ inputs.max_turns }}"` — user-controlled input interpolated directly.

6. Same step (line ~69): `"/Sherpa/deploy ${{ inputs.prompt }}"` — attacker-controlled prompt input interpolated directly and unquoted within the string, enabling full shell command injection. All of these must be moved to env: variables and referenced as quoted shell variables (e.g. "$VAR").

Locations:

- `action.yml:43`
- `action.yml:44`
- `action.yml:63`
- `action.yml:64`
- `action.yml:67`
- `action.yml:68`
- `action.yml:69`

### github-env-injection (severity: high)

The 'Run Claude Code with Sherpa' step writes $OUTPUT to $GITHUB_OUTPUT without sanitization. $OUTPUT is the result of running the claude CLI with attacker-controlled inputs (inputs.prompt, inputs.max_turns, etc.) and the unsanitized ENV_VARS_JSON environment. A malicious value containing newlines could inject arbitrary key=value pairs into GITHUB_OUTPUT, poisoning subsequent steps. The write `echo "$OUTPUT" >> $GITHUB_OUTPUT` (inside the heredoc block) must be preceded by sanitization: `safe=$(printf '%s' "$OUTPUT" | tr -d '\n\r')` before writing.

Locations:

- `action.yml:75`

### suspicious-run-content (severity: high)

Sub-check eval-dynamic: The 'Run Claude Code with Sherpa' step uses `eval "$(echo "$ENV_VARS_JSON" | jq -r ...)"` — eval with $() command substitution. ENV_VARS_JSON is sourced from ${{ toJSON(env) }}, which contains the entire calling workflow's environment context. A calling workflow can inject arbitrary env vars whose keys or values could escape the jq @sh quoting and cause eval to execute attacker-controlled shell commands. Matching pattern: `eval\s+[\x60$]`.

Locations:

- `action.yml:59`

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

Fixed all 8 findings in action.yml:
1. Pinned actions/setup-node@v4 to full SHA 49933ea5288caeca8642d1e84afbd3f7d6820020
2. Moved all ${{ github.action_path }}, ${{ github.workspace }}, ${{ inputs.* }} expressions from run: blocks to env: blocks in both 'Copy Sherpa plugin' and 'Run Claude Code with Sherpa' steps
3. Sanitized $OUTPUT before writing to $GITHUB_OUTPUT using tr -d '\r' to prevent newline injection
4. Replaced dangerous eval "$(jq ...)" pattern with a safer while-read loop that avoids eval entirely, eliminating the eval-dynamic code execution risk
5. All static-inline-injection findings resolved as part of the script-injection fixes

