# ansible-multiline-output

An Ansible stdout callback plugin that prints multiline `msg` output line by line and hides the values of secret variables. Created so ansible terminal output is easier to read, and easier to paste into, say, Claude for troubleshooting without also pasting your secrets.

```sh
ansible-galaxy collection install z0mbieparade.multiline_output
ANSIBLE_STDOUT_CALLBACK=z0mbieparade.multiline_output.multiline_output ansible-playbook site.yml
```

**Required:** ansible-core 2.19 or later.

## What it prints

```
TASK [Show config] *************************************************
ok: [web1] =>
──────────────────────────────────────────────────
url: https://[vault_domain]/api
token: [vault_api_token]
──────────────────────────────────────────────────
```

- **Multiline `msg`.** A successful result's `msg` prints line by line between
  borders. The default callback prints it as one JSON string full of `\n`.
  This applies wherever the default callback shows a successful result:
  `debug`, or any task with `-v`.
- **Secret redaction.** The value of each variable matching `redacted_vars`
  prints as `[<variable name>]`. The default pattern is `vault_*`. Inline
  `!vault` values and dictionary keys are redacted too.

Redaction covers:

- ok, changed, failed, skipped and unreachable results
- retries, loop items and async results
- `--diff`
- custom stats from `set_stats`

Failed, skipped and unreachable results keep the default layout. Status lines,
colors, warnings, `display_ok_hosts` and `callback_result_format` behave as in
the default callback.

## Install

From Galaxy:

```sh
ansible-galaxy collection install z0mbieparade.multiline_output
```

From the repository:

```sh
ansible-galaxy collection install git+https://github.com/z0mbieparade/ansible-multiline-output.git
```

## Enable

```ini
# ansible.cfg
[defaults]
stdout_callback = z0mbieparade.multiline_output.multiline_output
```

The environment variable works too:
`ANSIBLE_STDOUT_CALLBACK=z0mbieparade.multiline_output.multiline_output`.

## Options

```ini
# ansible.cfg
[callback_multiline_output]
redacted_vars = vault_*, *_password
unredacted_vars = vault_service_name
```

| Option | Default | Env | Description |
|---|---|---|---|
| `redacted_vars` | `['vault_*']` | `ANSIBLE_MULTILINE_OUTPUT_REDACTED_VARS` | Glob patterns of variable names whose values are redacted |
| `unredacted_vars` | `[]` | `ANSIBLE_MULTILINE_OUTPUT_UNREDACTED_VARS` | Glob patterns exempt from `redacted_vars`, for values that aren't secret but appear everywhere |

Every option of the default callback applies too. List them with
`ansible-doc -t callback z0mbieparade.multiline_output.multiline_output`.

## What redaction does not cover

**Warning:** redaction makes output readable and shareable. It is not a
security boundary. Use `no_log` for anything that must never be printed.

- Task and play names, module warnings and error tracebacks print as they are.
  Don't template a secret into a task name.
- Values shorter than 5 characters are not redacted.
- A value is only redacted as a whole word. `deploy` is redacted in
  `/home/deploy/` but not in `/home/deployer`.
- Values are read as defined in inventory, vars files, play or task vars, or
  extra vars. A templated value such as `"{{ lookup(...) }}"` is not rendered,
  so its result is not redacted.
- Variables created by `set_fact` or `register` are redacted from the next
  play on. They are not redacted in the play that creates them.
- Two dictionary keys that redact to the same placeholder show as one.
- Other callbacks get the original results. A JSON or log aggregator callback
  can record secrets in the clear. `log_path` records this callback's output, so
  it is redacted.

## Decisions

- **Whole-word matching.** A short value like the username `deploy` would
  otherwise turn `/home/deployer` into `/home/[vault_user]er`. The cost is that
  a secret glued to letters or digits prints in the clear. Real secrets sit
  between quotes, `=`, `:`, `@`, `/` or spaces.
- **5-character minimum.** Shorter values coincide with ordinary output too
  often. Keys, tokens and generated passwords are longer.
- **Output is never suppressed.** When redaction fails, the result prints
  unredacted with a warning. A failed task always shows its error.

## Development

```sh
python -m unittest discover -s tests/unit/plugins/callback
```

## License

[GPL-3.0-or-later](LICENSE), as required for Ansible controller plugins.
