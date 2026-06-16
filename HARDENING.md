<!-- markdownlint-disable -->

# Hardening Report: sherpa-sh--Sherpa-Action/v1.0.0-alpha.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **sherpa-sh--Sherpa-Action/v1.0.0-alpha.1** was hardened automatically. 8 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ }} expressions are directly interpolated inside run: shell command strings in the 'Copy Sherpa plugin to workspace' step. `${{ github.action_path }}` and `${{ github.workspace }}` are substituted directly into shell variable assignments before the shell ever sees them. While these particular github context values are not attacker-controlled, any ${{ }} in a run: block is a script-injection finding per the check rules.

Sub-rule (a) — more critically: In the 'Run Claude Code with Sherpa' step, attacker-controlled inputs are directly interpolated: `${{ inputs.anthropic_api_key }}`, `${{ inputs.github_token }}`, `${{ github.workspace }}`, `${{ inputs.max_turns }}`, and most dangerously `"/Sherpa/deploy ${{ inputs.prompt }}"` — the prompt input is injected directly into a shell command string, allowing an attacker to break out of the quoted string and execute arbitrary shell commands.

Locations:

- `action.yml:43`
- `action.yml:44`
- `action.yml:62`
- `action.yml:63`
- `action.yml:67`
- `action.yml:68`
- `action.yml:69`

### github-env-injection (severity: high)

The 'Run Claude Code with Sherpa' step writes `$OUTPUT` to `$GITHUB_OUTPUT` using a heredoc delimiter (result<<EOF). `$OUTPUT` is the stdout of the `claude` process, which was invoked with `inputs.prompt` directly interpolated into its command line. This value is entirely attacker-controlled and is written to $GITHUB_OUTPUT without any sanitization (`printf '%s' ... | tr -d '\n\r'`). An attacker can inject newlines into `inputs.prompt` to smuggle additional key=value pairs into GITHUB_OUTPUT, poisoning downstream step outputs.

Locations:

- `action.yml:71`
- `action.yml:72`
- `action.yml:73`
- `action.yml:74`

### suspicious-run-content (severity: high)

eval-dynamic: The 'Run Claude Code with Sherpa' step uses `eval "$(echo "$ENV_VARS_JSON" | jq -r ...)"` — eval with command substitution (`$(...)`) — to dynamically construct and execute shell export statements from the entire workflow environment context (`toJSON(env)`). This is the eval-dynamic pattern: it executes dynamically constructed shell code derived from external/workflow-controlled data. If any environment variable value contains shell metacharacters, this eval can execute arbitrary commands.

Locations:

- `action.yml:58`

### unpinned-uses (severity: high)

The action uses `actions/setup-node@v4` — a mutable tag reference rather than a pinned 40-character commit SHA. This means the action's dependency can be silently updated (or compromised via tag mutation) without the action author's knowledge, enabling supply-chain attacks. It should be pinned to a full SHA, e.g. `actions/setup-node@1d0ff469b4a3d2f5b32d7d7b5e3b5e3b5e3b5e3b # v4`.

Locations:

- `action.yml:37`

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
1. Pinned actions/setup-node@v4 to full SHA 49933ea5288caeca8642d1e84afbd3f7d6820020.
2. Moved ${{ github.action_path }} and ${{ github.workspace }} from the 'Copy Sherpa plugin' run: block to its env: block (ACTION_PATH, WORKSPACE).
3. Moved all ${{ inputs.* }} and ${{ github.workspace }} expressions from the 'Run Claude Code with Sherpa' run: block to its env: block (ANTHROPIC_API_KEY, GITHUB_TOKEN, WORKSPACE, MAX_TURNS, PROMPT).
4. Replaced the heredoc result<<EOF / echo "$OUTPUT" / EOF GITHUB_OUTPUT write with a random-delimiter printf-based approach to prevent heredoc injection.
5. Replaced eval "$(...)" with a write-to-tempfile + grep-validate + source pattern to eliminate dynamic eval of shell code from env context.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in 'Run Claude Code with Sherpa' step (action.yml line 88). Changed `"/Sherpa/deploy $PROMPT"` to `"/Sherpa/deploy" ${PROMPT:+"$PROMPT"}` — the command and the user-controlled PROMPT are now separate arguments. This prevents attacker-controlled values like `$(malicious_command)` from being interpreted as shell commands within the double-quoted string. The `${PROMPT:+"$PROMPT"}` form also correctly handles the optional empty-default input by dropping the argument entirely when PROMPT is empty.

