# Copyright: (c) z0mbieparade
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = '''
    name: multiline_output
    type: stdout
    author: z0mbieparade (@z0mbieparade)
    short_description: Ansible output with clean multiline msg display and secret redaction
    description:
        - "Usage: set C(stdout_callback = z0mbieparade.multiline_output.multiline_output)
          in the C([defaults]) section of ansible.cfg."
        - "Example: C(ANSIBLE_STDOUT_CALLBACK=z0mbieparade.multiline_output.multiline_output
          ansible-playbook site.yml)"
        - Prints the msg of a successful result line by line between borders.
        - Replaces the values of secret variables with C([<variable name>]) in
          task results, C(--diff) and custom stats.
    notes:
        - "Warning: task names, module warnings and error tracebacks are not redacted."
        - A value is only redacted as a whole word. C(deploy) is redacted in
          C(/home/deploy/) but not in C(/home/deployer).
        - Values shorter than 5 characters are not redacted.
        - If redaction fails, the result prints unredacted with a warning.
          A failed task always shows its error.
        - Failed, skipped and unreachable results keep the default layout.
    extends_documentation_fragment:
        - default_callback
        - result_format_callback
    options:
        redacted_vars:
            description:
                - Glob patterns of variable names whose values are secret.
                - Each value prints as C([<variable name>]).
            type: list
            elements: str
            default: ['vault_*']
            ini:
                - section: callback_multiline_output
                  key: redacted_vars
            env:
                - name: ANSIBLE_MULTILINE_OUTPUT_REDACTED_VARS
        unredacted_vars:
            description:
                - Glob patterns of variable names exempt from O(redacted_vars).
                - For values that match O(redacted_vars) but are not secret and
                  appear everywhere. A subdomain that is just the service's name
                  is one.
            type: list
            elements: str
            default: []
            ini:
                - section: callback_multiline_output
                  key: unredacted_vars
            env:
                - name: ANSIBLE_MULTILINE_OUTPUT_UNREDACTED_VARS
'''

import copy
import fnmatch
import itertools
import re
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from ansible.parsing.vault import EncryptedString
from ansible.plugins.callback.default import CallbackModule as DefaultCallback

if TYPE_CHECKING:
    from ansible.executor.stats import AggregateStats
    from ansible.executor.task_result import CallbackTaskResult
    from ansible.playbook.play import Play


def _redacting(hook: Callable[..., None], box_msg: bool = False) -> Callable[..., None]:
    """Return a DefaultCallback hook that redacts the result before printing it.

    The returned hook redacts the result in place and sets _box_msg while it
    prints. It raises whatever hook raises.

    hook: a DefaultCallback hook taking the result as its first argument
    box_msg: draw the result's msg as a box, see _dump_results
    """
    def redacting_hook(self: CallbackModule, result: CallbackTaskResult, *args: Any, **kwargs: Any) -> None:
        self._redact_result(result)
        self._box_msg = box_msg
        try:
            hook(self, result, *args, **kwargs)
        finally:
            self._box_msg = False
    return redacting_hook


class CallbackModule(DefaultCallback):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'z0mbieparade.multiline_output.multiline_output'

    # A short secret that coincides with common text would mangle ordinary
    # output. Keys, tokens and session secrets are comfortably longer.
    MIN_REDACT_LEN = 5

    def __init__(self) -> None:
        super().__init__()
        # secret value -> the variable it came from, shown in its place
        self._secret_values: dict[str, str] = {}
        # One alternation over every secret, rebuilt only when a secret is added
        self._secret_pattern: re.Pattern[str] | None = None
        self._secret_pattern_size = 0
        # Set only while an ok hook prints. See _dump_results.
        self._box_msg = False

    # ---- collection -------------------------------------------------------
    def _collect_secret_values(self, variables: Any) -> None:
        """Map the values of the variables redacted_vars names to their names for redaction.

        Adds to _secret_values. The first variable wins when two share a value.
        Raises whatever reading variables raises.

        variables: a mapping of variable names to values. Anything else is ignored.
        """
        if not isinstance(variables, Mapping):
            return
        for key, value in variables.items():
            if isinstance(key, str) and self._is_redacted(key):
                if isinstance(value, EncryptedString):
                    # Inline !vault values aren't str. str() decrypts them. One
                    # that can't be decrypted can't reach the output either.
                    try:
                        value = str(value)
                    except Exception:
                        continue
                if isinstance(value, str) and len(value) >= self.MIN_REDACT_LEN:
                    self._secret_values.setdefault(value, key)

    def _is_redacted(self, name: str) -> bool:
        """Whether redacted_vars names this variable and unredacted_vars doesn't exempt it.

        Raises KeyError from get_option before set_options has run.
        """
        def matches(option: str) -> bool:
            return any(fnmatch.fnmatchcase(name, pattern) for pattern in self.get_option(option))
        return matches('redacted_vars') and not matches('unredacted_vars')

    def v2_playbook_on_play_start(self, play: Play) -> None:
        """Collect every inventory host's secret values, then print the play banner.

        Adds to _secret_values. Raises nothing of its own: a failure to collect
        warns through _warn_unredacted.

        The full var set is the reliable source. task.get_vars() and host.vars
        don't surface inventory vault vars on their own. There is no public
        route to the variable manager, so this reads private attributes.
        It reads every host in the inventory, because any task can reach them
        through hostvars. It runs again each play, because play vars differ.
        On a large inventory that is a noticeable pause at each play start.
        """
        try:
            vm = getattr(play, '_variable_manager', None)
            inventory = getattr(vm, '_inventory', None) if vm else None
            if vm is not None and inventory is not None:
                for host in inventory.get_hosts():
                    host_vars = vm.get_vars(play=play, host=host)
                    self._collect_secret_values(host_vars)
        except Exception as e:
            self._warn_unredacted(e)
        super().v2_playbook_on_play_start(play)

    def _warn_unredacted(self, error: Exception) -> None:
        """Display a warning that secrets may print in the clear.

        Output is never suppressed when redaction fails, so this warning is
        how the operator finds out.

        error: the exception redaction raised
        """
        self._display.warning(f'multiline_output could not redact, so secrets may print in the clear: {error!r}')

    # ---- redaction --------------------------------------------------------
    def _redact_secrets(self, data: Any) -> Any:
        """Return a copy of data with every collected secret replaced by its placeholder.

        Strings, dicts and lists are redacted recursively. Other values, and all
        data while no secret is collected, are returned as they are. data is
        never changed. An inline !vault value that can't be decrypted is
        returned as it is. Raises RecursionError on data that contains itself.
        """
        if not self._secret_values:
            return data
        if isinstance(data, EncryptedString):
            # The default dump decrypts inline !vault values, so one in a
            # result would print in the clear. include_vars and set_fact
            # results can hold them.
            try:
                data = str(data)
            except Exception:
                return data
        if isinstance(data, str):
            return self._secret_regex().sub(
                lambda m: m.group(0) if m.group('placeholder') else f'[{self._secret_values[m.group(0)]}]', data)
        elif isinstance(data, dict):
            # Usernames, hostnames and paths are often map keys. Two keys that
            # redact to the same placeholder print as one.
            return {self._redact_secrets(k): self._redact_secrets(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._redact_secrets(item) for item in data]
        return data

    def _secret_regex(self) -> re.Pattern[str]:
        """Return one pattern matching every collected secret, longest first.

        Caches the pattern until a secret is added. Raises nothing.

        A single pass avoids a replace() per secret. Chained replaces rescan
        the placeholders already inserted. A short secret that is also a word
        in a variable name would then mangle them and hint at its own value.
        `admin` in vault_db_admin_password is one.

        The scan takes the leftmost match, so a value containing another is
        replaced whole. vault_app_url containing vault_domain is one case.
        Longest-first decides between secrets starting at the same place.
        The shorter one winning would print the rest of the longer secret in
        the clear.

        An existing placeholder is matched first and kept as it is, so
        redacting twice changes nothing. A result is redacted in place and its
        msg again when printed. That second pass must not rewrite
        `[vault_api_password]` when some secret's value is a word in that name.

        Each secret matches only as a whole token, see _token_pattern. A secret
        can fail that at a spot where a shorter secret inside it passes. It
        then prints in part around the shorter one's placeholder. Without the
        shorter secret it would print whole.
        """
        if self._secret_pattern is None or self._secret_pattern_size != len(self._secret_values):
            secrets = sorted(self._secret_values, key=len, reverse=True)
            self._secret_pattern = re.compile(
                r'(?P<placeholder>\[(?:' + '|'.join(re.escape(name) for name in set(self._secret_values.values()))
                + r')\])|' + '|'.join(self._token_pattern(secret) for secret in secrets))
            self._secret_pattern_size = len(self._secret_values)
        return self._secret_pattern

    @staticmethod
    def _token_pattern(secret: str) -> str:
        """Return a pattern matching secret only where it isn't part of a longer word.

        Raises nothing.

        Without the bounds, a username `deploy` turns /home/deployer into
        /home/[vault_...]er. Each end is bounded only where the secret itself
        ends in a letter or digit. A secret that starts or ends with
        punctuation or a newline already stops there. PEM keys and YAML block
        scalars do. Bounding that end too would print the secret whole whenever
        text follows without a gap. The cost is that a secret glued to letters
        or digits prints in the clear. Real secrets sit between quotes, `=`,
        `:`, `@`, `/` or spaces.

        secret: the secret's value, not its variable name
        """
        return ((r'(?<![^\W_])' if secret[0].isalnum() else '') + re.escape(secret)
                + (r'(?![^\W_])' if secret[-1].isalnum() else ''))

    def _redact_result(self, result: CallbackTaskResult) -> None:
        """Redact secrets in place on a result, without ever emptying it.

        Replaces the contents of result.result and adds the task's secrets to
        _secret_values. Raises nothing: every failure warns through
        _warn_unredacted. When the task's vars can't be read, the result is
        still redacted against the secrets already collected. When redacting
        fails, the result is left as it was.
        """
        # Task vars can hold secrets the play start didn't see.
        try:
            self._collect_secret_values(result.task.get_vars())
        except Exception as e:
            self._warn_unredacted(e)

        # A deep copy can fail, and with no secrets there is nothing to gain from one.
        if not self._secret_values:
            return

        try:
            res = result.result
            if isinstance(res, dict):
                redacted = self._redact_secrets(copy.deepcopy(res))
                if isinstance(redacted, dict):
                    res.clear()
                    res.update(redacted)
        except Exception as e:
            # The original result stays intact, so a failed task still shows its error.
            self._warn_unredacted(e)

    # ---- display ----------------------------------------------------------
    def _msg_box(self, msg: Any) -> str | None:
        """Return msg as lines between two borders, or None if there is nothing to show.

        Raises what _redact_secrets raises.

        msg: a result's msg. A list of strings prints one per line. Anything
            else is left to the default dump, which serializes it properly.
        """
        # _redact_result leaves the result untouched when it hits an exception.
        # An uncopyable value makes its deep copy raise. This is the text that
        # reaches the terminal, so it is redacted again. Redaction is idempotent.
        msg = self._redact_secrets(msg)

        if isinstance(msg, list) and all(isinstance(line, str) for line in msg):
            lines = msg
        elif isinstance(msg, str):
            # Stripping the first line's indent would misalign it with the
            # lines below, so only blank lines are trimmed.
            lines = list(itertools.dropwhile(lambda line: not line.strip(), msg.rstrip().splitlines()))
        else:
            return None
        if not lines:
            return None

        border = '─' * 50
        return '\n'.join([border, *lines, border])

    def _get_item_label(self, result: Mapping[str, Any]) -> Any:
        """Return the default loop item label, redacted.

        Raises what _redact_secrets raises.

        This runs here rather than in a hook because v2_playbook_on_include
        prints the label from the IncludedFile's vars. The strategy still runs
        the include with those vars, so they must not be redacted in place.

        result: a task result, or an include's vars
        """
        return self._redact_secrets(super()._get_item_label(result))

    def _dump_results(self, result: Mapping[str, Any], indent: int | None = None, sort_keys: bool = True,
                      keep_invocation: bool = False, serialize: bool = True) -> Any:
        """Dump a result as the default callback does, with its msg drawn as a box below the rest.

        The box is drawn only while an ok hook prints. Overriding the dump
        rather than the hooks keeps the default's status line, colors, task
        banner, warnings and display_ok_hosts. Failures and custom stats are
        dumped here too. Stats are flattened onto one line.

        Parameters, return and exceptions are those of CallbackBase._dump_results.
        """
        box = self._msg_box(result.get('msg')) if self._box_msg and serialize else None
        if box is None:
            return super()._dump_results(result, indent, sort_keys, keep_invocation, serialize)

        rest = {key: value for key, value in result.items() if key != 'msg'}
        if not super()._dump_results(rest, keep_invocation=keep_invocation, serialize=False):
            return '\n' + box
        # The yaml format ends its dump with a newline and json doesn't.
        return super()._dump_results(rest, indent, sort_keys, keep_invocation).rstrip('\n') + '\n' + box

    # ---- hooks ------------------------------------------------------------
    # A hook that prints a task result and is missing here prints it
    # unredacted. --diff prints through v2_on_file_diff, before
    # v2_runner_on_ok and once per loop item.
    v2_runner_on_ok = _redacting(DefaultCallback.v2_runner_on_ok, box_msg=True)
    v2_runner_item_on_ok = _redacting(DefaultCallback.v2_runner_item_on_ok, box_msg=True)
    v2_runner_on_failed = _redacting(DefaultCallback.v2_runner_on_failed)
    v2_runner_item_on_failed = _redacting(DefaultCallback.v2_runner_item_on_failed)
    v2_runner_on_skipped = _redacting(DefaultCallback.v2_runner_on_skipped)
    v2_runner_item_on_skipped = _redacting(DefaultCallback.v2_runner_item_on_skipped)
    v2_runner_on_unreachable = _redacting(DefaultCallback.v2_runner_on_unreachable)
    v2_runner_retry = _redacting(DefaultCallback.v2_runner_retry)
    v2_runner_on_async_poll = _redacting(DefaultCallback.v2_runner_on_async_poll)
    v2_runner_on_async_ok = _redacting(DefaultCallback.v2_runner_on_async_ok)
    v2_runner_on_async_failed = _redacting(DefaultCallback.v2_runner_on_async_failed)
    v2_on_file_diff = _redacting(DefaultCallback.v2_on_file_diff)

    def v2_playbook_on_stats(self, stats: AggregateStats) -> None:
        """Print the recap as the default callback does, with set_stats data redacted.

        stats is not changed. Raises nothing of its own: a redaction failure
        warns through _warn_unredacted and prints the stats unredacted.
        """
        # Every callback is passed the same stats, so redact a copy.
        redacted_stats = copy.copy(stats)
        try:
            redacted_stats.custom = self._redact_secrets(stats.custom)
        except Exception as e:
            self._warn_unredacted(e)
        super().v2_playbook_on_stats(redacted_stats)
