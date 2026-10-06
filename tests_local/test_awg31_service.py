#!/usr/bin/env python3
"""Проверки отдельной временной службы без внешних системных изменений."""

import base64
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'deployment' / 'awg31_service.py'
spec = importlib.util.spec_from_file_location('awg31_service', str(PATH))
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


def args():
    return SimpleNamespace(endpoint='198.51.100.42', port=5182, network='10.92.46.0/24',
                           wan='ens3', go_sha256='a' * 64, awg_sha256='b' * 64)


def manifest():
    return {'endpoint': '198.51.100.42', 'port': 5182, 'network': '10.92.46.0/24', 'wan': 'ens3',
            'server_ip': '10.92.46.1', 'server_public_key': base64.b64encode(b'A' * 32).decode(),
            'peers': [{'name': name, 'ip': '10.92.46.' + str(index),
                       'public_key': base64.b64encode(bytes([index]) * 32).decode()}
                      for index, name in enumerate(service.PEER_NAMES, 2)], 'old_forward': '0',
            'go_sha256': 'a' * 64, 'awg_sha256': 'b' * 64}


class TestServiceInputs(unittest.TestCase):
    def test_private_only_strict24_and_safe_interface(self):
        for changes in ({'network': '192.0.2.0/24'}, {'network': '10.0.0.1/24'},
                        {'network': '10.0.0.0/16'}, {'port': 0}, {'port': 65536},
                        {'wan': 'ens3;delete'}, {'wan': service.INTERFACE}):
            values = vars(args()).copy()
            values.update(changes)
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                service.validate_inputs(values['endpoint'], values['port'], values['network'], values['wan'])
        endpoint, network = service.validate_inputs('198.51.100.42', 5182, '10.92.46.0/24', 'ens3')
        self.assertEqual(str(network), '10.92.46.0/24')

    def test_wan_requires_standard_policy_and_actual_endpoint(self):
        policy = [{'priority': priority, 'src': 'all', 'table': table}
                  for priority, table in ((0, 'local'), (32766, 'main'), (32767, 'default'))]
        addresses = [{'flags': ['UP'], 'addr_info': [{'local': '198.51.100.42'}]}]
        def answer(argv, **kwargs):
            if 'route' in argv:
                return json.dumps([{'dev': 'ens3'}])
            if 'rule' in argv:
                return json.dumps(policy)
            return json.dumps(addresses)
        with patch.object(service, 'run', side_effect=answer):
            service.validate_wan(manifest())
            policy.append({'priority': 100, 'src': 'all', 'table': 100})
            with self.assertRaises(RuntimeError):
                service.validate_wan(manifest())
            policy.pop()
            addresses[0]['addr_info'][0]['local'] = '198.51.100.43'
            with self.assertRaises(RuntimeError):
                service.validate_wan(manifest())

    def test_rule_baseline_preserves_output_but_rejects_affected_rules(self):
        baseline = '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A OUTPUT -p tcp -j ACCEPT\nCOMMIT\n*nat\n:POSTROUTING ACCEPT [0:0]\nCOMMIT'
        service.clean_baseline(baseline)
        for extra in ('-A INPUT -j DROP', '-A FORWARD -j ACCEPT', ':INPUT DROP [0:0]', ':LF31-IN - [0:0]'):
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                service.clean_baseline('*filter\n' + extra)

    def test_firewall_counters_and_timestamps_are_not_configuration_changes(self):
        first = '# Generated at time1\n*filter\n:INPUT ACCEPT [12:240]\nCOMMIT'
        second = '# Generated at time2\n*filter\n:INPUT ACCEPT [24:480]\nCOMMIT'
        self.assertEqual(service.firewall_identity(first), service.firewall_identity(second))
        self.assertNotEqual(service.firewall_identity(first), service.firewall_identity(second + '\n-A INPUT -j DROP'))

    def test_existing_state_refuses_before_external_operations(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / 'state'
            existing.mkdir()
            with patch.object(service, 'STATE', existing), patch.object(service, 'run') as run:
                with self.assertRaises(RuntimeError):
                    service.preflight(args())
                run.assert_not_called()

    def test_untrusted_script_never_enters_provision(self):
        with patch.object(service.os, 'geteuid', return_value=0, create=True):
            with self.assertRaises(RuntimeError):
                service.require_root()
        with patch.object(service.os, 'geteuid', return_value=1000, create=True):
            with self.assertRaises(RuntimeError):
                service.require_root()

    def test_system_errors_do_not_expose_stdout_stderr_or_input(self):
        secret = 'sensitive-secret'
        response = SimpleNamespace(returncode=1, stdout=secret, stderr=secret)
        with patch.object(service.subprocess, 'run', return_value=response):
            with self.assertRaises(RuntimeError) as caught:
                service.run(['awg', 'pubkey'], data=secret)
        self.assertNotIn(secret, str(caught.exception))


class TestStagedState(unittest.TestCase):
    def test_duplicate_peer_key_in_saved_state_is_rejected(self):
        data = manifest()
        data['peers'][1]['public_key'] = data['peers'][0]['public_key']
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / 'manifest.json').write_text(json.dumps(data))
            (state / 'manifest.json').chmod(0o600)
            with patch.object(service, 'STATE', state), patch.object(service, 'trusted'):
                with self.assertRaises(RuntimeError):
                    service.load_manifest()

    def test_unknown_prior_forwarding_stops_before_state_commit(self):
        counter = iter(range(1, 7))
        def pair():
            num = next(counter)
            return (base64.b64encode(bytes([num]) * 32).decode(),
                    base64.b64encode(bytes([num + 20]) * 32).decode())
        with tempfile.TemporaryDirectory() as tmp, patch.object(service, 'ROOT', Path(tmp)), \
             patch.object(service, 'new_keypair', side_effect=pair), patch.object(service, 'run', return_value='unknown'):
            _, network = service.validate_inputs(args().endpoint, args().port, args().network, args().wan)
            with self.assertRaises(RuntimeError):
                service.stage_state(args(), args().endpoint, network, 'baseline')
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_server_includes_both_peers_and_full_modern_profile(self):
        counter = iter(range(1, 7))
        def pair():
            num = next(counter)
            return (base64.b64encode(bytes([num]) * 32).decode(),
                    base64.b64encode(bytes([num + 20]) * 32).decode())
        with tempfile.TemporaryDirectory() as tmp, patch.object(service, 'ROOT', Path(tmp)), \
             patch.object(service, 'new_keypair', side_effect=pair), patch.object(service, 'run', return_value='0'):
            _, network = service.validate_inputs(args().endpoint, args().port, args().network, args().wan)
            staging, data = service.stage_state(args(), args().endpoint, network, 'baseline')
            text = (staging / 'server.conf').read_text()
            self.assertEqual(text.count('[Peer]'), 2)
            for peer in data['peers']:
                self.assertIn('PublicKey = ' + peer['public_key'], text)
                self.assertIn('AllowedIPs = ' + peer['ip'] + '/32', text)
            for key in service.PROFILE_KEYS:
                self.assertIn(key + ' = ', text)
            for name in service.PEER_NAMES:
                client = staging / (name + '.conf')
                if os.name == 'posix':
                    self.assertEqual(client.stat().st_mode & 0o777, 0o600)
                self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', client.read_text())
                self.assertIn('Endpoint = 198.51.100.42:5182', client.read_text())
            stored = json.loads((staging / 'manifest.json').read_text())
            self.assertNotIn('HeaderProtectionKey', stored)
            self.assertNotIn('PrivateKey', stored)
            if os.name == 'posix':
                self.assertEqual(staging.stat().st_mode & 0o777, 0o700)

    def test_zero_keys_are_rejected_and_header_generation_is_bounded(self):
        with self.assertRaises(RuntimeError):
            service.key_valid(base64.b64encode(bytes(32)).decode())
        with patch.object(service.secrets, 'token_bytes', return_value=bytes(32)) as generate:
            with self.assertRaises(RuntimeError):
                service.header_key()
            self.assertEqual(generate.call_count, 3)

    def test_key_generation_uses_stdin_and_sanitized_failure(self):
        key = base64.b64encode(b'A' * 32).decode()
        with patch.object(service, 'run', side_effect=[key, key]) as run:
            self.assertEqual(service.new_keypair(), (key, key))
            self.assertEqual(run.call_args_list[1].kwargs['data'], key + '\n')

    def test_file_creation_never_overwrites_existing_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'secret'
            service.write_private(path, 'original')
            with self.assertRaises(FileExistsError):
                service.write_private(path, 'replacement')
            self.assertEqual(path.read_text(), 'original')


class TestRulesAndService(unittest.TestCase):
    def test_iptables_option_reordering_is_equivalent_but_extra_rules_are_not(self):
        expected = ['-A', 'LF31-FWD', '-i', 'lfawg0', '-s', '10.92.46.2/32', '-o', 'ens3', '-j', 'ACCEPT']
        printed = ['-A', 'LF31-FWD', '-s', '10.92.46.2/32', '-i', 'lfawg0', '-o', 'ens3', '-j', 'ACCEPT']
        self.assertEqual(service.normalized_rule(expected), service.normalized_rule(printed))
        foreign = printed + ['-m', 'comment', '--comment', 'foreign']
        self.assertNotEqual(service.normalized_rule(expected), service.normalized_rule(foreign))

    def test_interface_left_after_stop_is_not_deleted_by_name(self):
        replies = ['', 'inactive', '0', json.dumps([{'ifname': service.INTERFACE}])]
        with patch.object(service, 'run', side_effect=replies) as run, \
             patch.object(service.shutil, 'rmtree') as remove:
            self.assertTrue(service.rollback(manifest(), [('state', service.STATE), ('unit', service.UNIT)]))
            remove.assert_not_called()
            self.assertFalse(any('delete' in call.args[0] for call in run.call_args_list))

    def test_rules_allow_exact_peers_and_end_in_drop(self):
        data = manifest()
        rules = service.rules(data)
        forward = [spec for table, chain, spec in rules if chain == service.CHAIN_FWD]
        self.assertEqual(forward[-2:], [['-i', service.INTERFACE, '-j', 'DROP'],
                                       ['-o', service.INTERFACE, '-j', 'DROP']])
        nat = [spec for table, chain, spec in rules if table == 'nat']
        self.assertEqual(len(nat), 2)
        self.assertTrue(all('-s' in spec and spec[spec.index('-s') + 1].endswith('/32') for spec in nat))
        self.assertFalse(any('OUTPUT' in chain for _, chain, _ in rules))

    def test_unit_uses_foreground_and_restarts_clean_failure(self):
        text = service.unit_text()
        self.assertIn('Type=simple', text)
        self.assertIn(' -f lfawg0', text)
        self.assertIn('WG_PROCESS_FOREGROUND=1', text)
        self.assertIn('Restart=always', text)
        self.assertIn('Environment=GOMEMLIMIT=256MiB', text)
        self.assertIn('MemoryMax=512M', text)
        self.assertIn('After=network-online.target systemd-sysctl.service', text)
        self.assertNotIn('PrivateDevices', text)
        self.assertIn('--internal-configure', text)

    def test_reboot_recreates_rules_before_validation(self):
        events = []
        with patch.object(service, 'run', return_value='*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT'), \
             patch.object(service, 'firewall', side_effect=lambda *x: events.append('create')), \
             patch.object(service, 'verify_firewall', side_effect=lambda *x: events.append('verify')):
            service.ensure_firewall(manifest())
        self.assertEqual(events, ['create', 'verify'])

    def test_firewall_hooks_require_exact_order_and_no_foreign_bypass(self):
        data = manifest()
        def output(argv, **kwargs):
            table = argv[argv.index('-t') + 1]
            chain = argv[-1]
            if chain in (service.CHAIN_IN, service.CHAIN_FWD, service.CHAIN_NAT):
                values = [['-A', chain] + spec for t, c, spec in service.rules(data) if (t, c) == (table, chain)]
                return '\n'.join(' '.join(item) for item in values)
            values = [['-A', chain] + spec for t, c, spec in reversed(service.hooks(data)) if (t, c) == (table, chain)]
            return '-P {} ACCEPT\n'.format(chain) + '\n'.join(' '.join(item) for item in values)
        with patch.object(service, 'run', side_effect=output):
            service.verify_firewall(data)
        def foreign(argv, **kwargs):
            result = output(argv, **kwargs)
            if argv[-1] == 'FORWARD':
                result += '\n-A FORWARD -j ACCEPT'
            return result
        with patch.object(service, 'run', side_effect=foreign), self.assertRaises(RuntimeError):
            service.verify_firewall(data)
        def wrong_order(argv, **kwargs):
            result = output(argv, **kwargs)
            if argv[-1] == 'FORWARD':
                lines = result.splitlines()
                result = '\n'.join([lines[0]] + list(reversed(lines[1:])))
            return result
        with patch.object(service, 'run', side_effect=wrong_order), self.assertRaises(RuntimeError):
            service.verify_firewall(data)

    def test_partial_rules_refuse_start_instead_of_flush(self):
        with patch.object(service, 'run', return_value=':LF31-IN - [0:0]'), \
             patch.object(service, 'firewall') as create:
            with self.assertRaises(RuntimeError):
                service.ensure_firewall(manifest())
            create.assert_not_called()

    def test_runtime_mismatch_never_exposes_hpk(self):
        params = service.profile()
        secret = params['HeaderProtectionKey']
        def response(argv, **kwargs):
            if argv[-1] == 'header-protection-key':
                return 'wrong-secret'
            reverse = {value: key for key, value in service.SELECTORS.items()}
            return params[reverse[argv[-1]]]
        with patch.object(service, 'server_profile', return_value=params), patch.object(service, 'run', side_effect=response):
            with self.assertRaises(RuntimeError) as caught:
                service.verify_runtime(manifest())
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn('wrong-secret', str(caught.exception))

    def test_rollback_with_failed_stop_preserves_keys_and_firewall(self):
        commands = []
        def fail(argv, **kwargs):
            commands.append(argv)
            raise RuntimeError('stop failed')
        with patch.object(service, 'run', side_effect=fail), patch.object(service.shutil, 'rmtree') as remove:
            self.assertTrue(service.rollback(manifest(), [('state', service.STATE), ('unit', service.UNIT)]))
            remove.assert_not_called()
        self.assertFalse(any('iptables' in command for command in commands))

    def test_rollback_verifies_inactive_before_deleting_interface_or_protection(self):
        commands = []
        def active(argv, **kwargs):
            commands.append(argv)
            if '--property=ActiveState' in argv:
                return 'active'
            if '--property=MainPID' in argv:
                return '123'
            return ''
        with patch.object(service, 'run', side_effect=active), patch.object(service.shutil, 'rmtree') as remove:
            self.assertTrue(service.rollback(manifest(), [('state', service.STATE), ('unit', service.UNIT)]))
            remove.assert_not_called()
        self.assertFalse(any('ip' in command or 'iptables' in command for command in commands))

    def test_rollback_before_first_mutation_touches_nothing(self):
        with patch.object(service, 'run') as run, patch.object(service.shutil, 'rmtree') as remove:
            self.assertFalse(service.rollback(manifest(), []))
            run.assert_not_called()
            remove.assert_not_called()

    def test_setconf_failure_never_bring_interface_up(self):
        data = manifest()
        info = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0)
        commands = []
        def execute(argv, **kwargs):
            commands.append(argv)
            if 'setconf' in argv:
                raise RuntimeError('failure')
            return ''
        with patch.object(service, 'load_manifest', return_value=data), \
             patch.object(service, 'validate_wan'), patch.object(service, 'trusted'), \
             patch.object(service.Path, 'exists', return_value=True), \
             patch.object(service.Path, 'lstat', return_value=info), \
             patch.object(service, 'ensure_firewall'), patch.object(service, 'run', side_effect=execute):
            with self.assertRaises(RuntimeError):
                service.configure()
        self.assertFalse(any('up' in command for command in commands))


if __name__ == '__main__':
    unittest.main()
