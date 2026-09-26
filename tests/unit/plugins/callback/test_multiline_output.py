# Copyright: (c) z0mbieparade
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import pathlib
import unittest
from unittest import mock

from ansible import context
from ansible.executor.stats import AggregateStats
from ansible.inventory.host import Host
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from ansible.parsing.vault import EncryptedString, VaultLib, VaultSecret, VaultSecretsContext
from ansible.playbook.play import Play
from ansible.playbook.task import Task
from ansible.plugins.callback.default import CallbackModule as DefaultCallback
from ansible.plugins.loader import callback_loader
from ansible.vars.manager import VariableManager

PLUGIN_DIR = pathlib.Path(__file__).parents[4] / 'plugins' / 'callback'
callback_loader.add_directory(str(PLUGIN_DIR))

BORDER = '─' * 50
VAULT_SECRET = VaultSecret(b'password')
DEBUG_TASK = {'debug': {'msg': 'x'}}


def make_callback(secrets: dict[str, str] | None = None, **options):
    """Return the plugin with its options set and secrets collected, its display a mock.

    secrets: variable name -> secret value
    options: plugin options overriding their defaults
    """
    callback = callback_loader.get('multiline_output')
    callback.set_options(direct=options)
    callback._display = mock.Mock(verbosity=0)
    callback._collect_secret_values(secrets or {})
    return callback


def vaulted(value: str) -> EncryptedString:
    """Return value as an inline !vault string, decryptable inside vault_secrets_loaded()."""
    return EncryptedString(ciphertext=VaultLib([('default', VAULT_SECRET)]).encrypt(value).decode())


def vault_secrets_loaded():
    """Return a context in which vaulted() values decrypt, as during a playbook run."""
    return mock.patch.object(VaultSecretsContext, '_current', VaultSecretsContext([('default', VAULT_SECRET)]))


def displayed(callback) -> list[str]:
    """Return the text the callback has displayed so far, one entry per display call."""
    return [call.args[0] for call in callback._display.display.call_args_list]


class FakeResult:
    """The parts of CallbackTaskResult the plugin and the default callback read."""

    def __init__(self, task_data: dict, result: dict) -> None:
        """
        task_data: a task as written in a playbook
        result: the task's result
        """
        self.task = Task.load(task_data)
        self.host = Host('localhost')
        self.result = result


def run_hook(callback, hook: str, task_data: dict, result: dict) -> list[str]:
    """Pass a result to one of the callback's hooks and return what it displayed.

    Marks the task's banner as printed, so the output holds only the result.

    hook: the hook's name
    task_data: a task as written in a playbook
    result: the task's result
    """
    task_result = FakeResult(task_data, result)
    callback._last_task_banner = task_result.task._uuid
    getattr(callback, hook)(task_result)
    return displayed(callback)


class RedactionTest(unittest.TestCase):
    def redact(self, secrets: dict[str, str], text: str) -> str:
        """Return text redacted against secrets.

        secrets: variable name -> secret value
        """
        return make_callback(secrets)._redact_secrets(text)

    def test_replaces_value_with_variable_name(self):
        self.assertEqual(self.redact({'vault_token': 'hunter22'}, 'token=hunter22'), 'token=[vault_token]')

    def test_leaves_value_inside_longer_word(self):
        self.assertEqual(self.redact({'vault_user': 'deploy'}, '/home/deployer /home/deploy/'),
                         '/home/deployer /home/[vault_user]/')

    def test_longer_secret_wins_over_one_it_contains(self):
        secrets = {'vault_domain': 'example.com', 'vault_app_url': 'https://app.example.com'}
        self.assertEqual(self.redact(secrets, 'url: https://app.example.com'), 'url: [vault_app_url]')

    def test_secret_that_is_a_word_in_a_placeholder_keeps_the_placeholder(self):
        secrets = {'vault_db_admin_password': 's3cretpass', 'vault_admin_user': 'admin'}
        self.assertEqual(self.redact(secrets, 'admin:s3cretpass'), '[vault_admin_user]:[vault_db_admin_password]')

    def test_redacting_twice_changes_nothing(self):
        callback = make_callback({'vault_db_admin_password': 's3cretpass', 'vault_admin_user': 'admin'})
        once = callback._redact_secrets('admin:s3cretpass')
        self.assertEqual(callback._redact_secrets(once), once)

    def test_secret_ending_in_punctuation_is_redacted_when_text_follows(self):
        key = '-----BEGIN KEY-----\nabc\n-----END KEY-----\n'
        self.assertEqual(self.redact({'vault_key': key}, key + 'next'), '[vault_key]next')

    def test_dict_keys_are_redacted(self):
        callback = make_callback({'vault_user': 'deployuser'})
        self.assertEqual(callback._redact_secrets({'deployuser': {'uid': 1001}}), {'[vault_user]': {'uid': 1001}})

    def test_short_values_are_not_secrets(self):
        self.assertEqual(self.redact({'vault_port': '22'}, 'port 22'), 'port 22')

    def test_unredacted_vars_exempts_a_match(self):
        callback = make_callback({'vault_service': 'gateway', 'vault_token': 'hunter22'},
                                 unredacted_vars=['vault_service'])
        self.assertEqual(callback._redact_secrets('gateway hunter22'), 'gateway [vault_token]')

    def test_inline_vault_value_is_decrypted_and_redacted(self):
        with vault_secrets_loaded():
            text = self.redact({'vault_token': vaulted('hunter22')}, 'token=hunter22')
        self.assertEqual(text, 'token=[vault_token]')

    def test_result_without_secrets_is_left_alone(self):
        callback = make_callback()
        result = FakeResult(DEBUG_TASK, {'msg': 'hello', 'changed': False})
        callback._redact_result(result)
        self.assertEqual(result.result, {'msg': 'hello', 'changed': False})

    def test_failed_redaction_warns(self):
        callback = make_callback({'vault_token': 'hunter22'})
        with mock.patch('copy.deepcopy', side_effect=TypeError('uncopyable')):
            callback._redact_result(FakeResult(DEBUG_TASK, {'msg': 'hunter22'}))
        callback._display.warning.assert_called_once()


class HookRedactionTest(unittest.TestCase):
    def assert_redacted(self, lines: list[str]) -> None:
        """Assert the secret hunter22 was displayed only as its placeholder."""
        text = '\n'.join(lines)
        self.assertIn('[vault_token]', text)
        self.assertNotIn('hunter22', text)

    def test_skipped_loop_item_label(self):
        self.assert_redacted(run_hook(make_callback({'vault_token': 'hunter22'}), 'v2_runner_item_on_skipped',
                                      DEBUG_TASK, {'item': 'hunter22', 'skipped': True, 'changed': False}))

    def test_unreachable_host(self):
        self.assert_redacted(run_hook(make_callback({'vault_token': 'hunter22'}), 'v2_runner_on_unreachable',
                                      DEBUG_TASK, {'msg': 'Failed to connect: hunter22@h', 'unreachable': True}))

    def test_inline_vault_value_in_a_result(self):
        callback = make_callback({'vault_token': 'hunter22'})
        callback._display.verbosity = 1
        with vault_secrets_loaded():
            self.assert_redacted(run_hook(callback, 'v2_runner_on_ok', {'include_vars': {'file': 'x'}},
                                          {'ansible_facts': {'vault_token': vaulted('hunter22')}, 'changed': False}))

    def test_include_loop_item_label(self):
        callback = make_callback({'vault_token': 'hunter22'})
        included_vars = {'item': 'hunter22'}
        callback.v2_playbook_on_include(
            mock.Mock(_filename='t.yml', _hosts=[Host('localhost')], _vars=included_vars))
        self.assert_redacted(displayed(callback))
        self.assertEqual(included_vars, {'item': 'hunter22'})

    def test_diff(self):
        diff = {'before': 'token: old\n', 'after': 'token: hunter22\n',
                'before_header': 'a.conf', 'after_header': 'a.conf'}
        self.assert_redacted(run_hook(make_callback({'vault_token': 'hunter22'}), 'v2_on_file_diff',
                                      {'copy': {'src': 'a', 'dest': 'b'}}, {'diff': [diff], 'changed': True}))

    def test_custom_stats(self):
        callback = make_callback({'vault_token': 'hunter22'}, show_custom_stats=True)
        stats = AggregateStats()
        stats.set_custom_stats('token', 'hunter22')
        stats.set_custom_stats('token', 'hunter22', host='localhost')
        with mock.patch.object(context, 'CLIARGS', {'check': False}):
            callback.v2_playbook_on_stats(stats)
        self.assert_redacted(displayed(callback))
        # Other callbacks are passed the same stats
        self.assertEqual(stats.custom['_run'], {'token': 'hunter22'})


class PlayStartTest(unittest.TestCase):
    def test_collects_every_inventory_hosts_secrets(self):
        loader = DataLoader()
        inventory = InventoryManager(loader=loader, sources='web1,db1,')
        inventory.get_host('db1').set_variable('vault_db_password', 'hunter22')
        variable_manager = VariableManager(loader=loader, inventory=inventory)
        play = Play.load({'hosts': 'web1', 'tasks': []}, variable_manager=variable_manager, loader=loader)
        callback = make_callback()
        callback.v2_playbook_on_play_start(play)
        self.assertEqual(callback._secret_values, {'hunter22': 'vault_db_password'})

    def test_unreadable_variables_warn(self):
        play = mock.Mock()
        play._variable_manager._inventory.get_hosts.return_value = [Host('web1')]
        play._variable_manager.get_vars.side_effect = RuntimeError('boom')
        callback = make_callback()
        with mock.patch.object(DefaultCallback, 'v2_playbook_on_play_start'):
            callback.v2_playbook_on_play_start(play)
        callback._display.warning.assert_called_once()


class OkOutputTest(unittest.TestCase):
    def test_debug_msg_is_boxed_under_the_status_line(self):
        lines = run_hook(make_callback(), 'v2_runner_on_ok', DEBUG_TASK,
                         {'msg': 'line one\nline two', 'changed': False, '_ansible_verbose_always': True})
        self.assertEqual(lines, [f'ok: [localhost] => \n{BORDER}\nline one\nline two\n{BORDER}'])

    def test_msg_keeps_its_indentation_and_loses_blank_lines(self):
        lines = run_hook(make_callback(), 'v2_runner_on_ok', DEBUG_TASK,
                         {'msg': '\n  \n  PID CMD\n  1   init\n\n', 'changed': False,
                          '_ansible_verbose_always': True})
        self.assertEqual(lines, [f'ok: [localhost] => \n{BORDER}\n  PID CMD\n  1   init\n{BORDER}'])

    def test_changed_result_keeps_changed_status(self):
        lines = run_hook(make_callback(), 'v2_runner_on_ok', DEBUG_TASK,
                         {'msg': 'done', 'changed': True, '_ansible_verbose_always': True})
        self.assertTrue(lines[0].startswith('changed: [localhost] => '))

    def test_module_msg_is_not_shown_without_verbosity(self):
        lines = run_hook(make_callback(), 'v2_runner_on_ok', {'uri': {'url': 'http://x'}},
                         {'msg': 'OK (12 bytes)', 'changed': False})
        self.assertEqual(lines, ['ok: [localhost]'])

    def test_verbose_module_result_dumps_the_rest_above_the_box(self):
        for result_format, rest in (('json', '{"changed": false, "status": 200}'),
                                    ('yaml', '\n    changed: false\n    status: 200')):
            with self.subTest(result_format=result_format):
                callback = make_callback(result_format=result_format)
                callback._display.verbosity = 1
                lines = run_hook(callback, 'v2_runner_on_ok', {'uri': {'url': 'http://x'}},
                                 {'msg': 'OK (12 bytes)', 'changed': False, 'status': 200})
                self.assertEqual(lines, [f'ok: [localhost] => {rest}\n{BORDER}\nOK (12 bytes)\n{BORDER}'])

    def test_list_of_non_strings_is_left_to_the_default_dump(self):
        lines = run_hook(make_callback(), 'v2_runner_on_ok', DEBUG_TASK,
                         {'msg': [{'a': 1}, None], 'changed': False, '_ansible_verbose_always': True})
        self.assertNotIn(BORDER, lines[0])
        self.assertIn('null', lines[0])

    def test_display_ok_hosts_false_prints_nothing(self):
        lines = run_hook(make_callback(display_ok_hosts=False), 'v2_runner_on_ok', DEBUG_TASK,
                         {'msg': 'hidden', 'changed': False, '_ansible_verbose_always': True})
        self.assertEqual(lines, [])

    def test_boxed_msg_is_redacted(self):
        lines = run_hook(make_callback({'vault_token': 'hunter22'}), 'v2_runner_on_ok', DEBUG_TASK,
                         {'msg': 'token=hunter22', 'changed': False, '_ansible_verbose_always': True})
        self.assertIn('token=[vault_token]', lines[0])
        self.assertNotIn('hunter22', lines[0])

    def test_failure_msg_is_not_boxed(self):
        self.assertEqual(make_callback()._dump_results({'msg': 'boom'}), '{"msg": "boom"}')


if __name__ == '__main__':
    unittest.main()
