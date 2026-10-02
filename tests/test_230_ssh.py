"""Exercise the actual embedded password-only policy without touching host SSH."""
import contextlib
import io
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from common import SCRIPT, module, payload


class Password230Tests(unittest.TestCase):
    def setUp(self):
        self.h = module('VK_SSH_GUARD_PY')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.shadow = self.root / 'shadow'
        self.row = 'operator:$y$test_ephemeral_not_a_password_hash:19000:0:99999:7:::\n'
        self.shadow.write_text(self.row); self.shadow.chmod(0o600)
        self.account = SimpleNamespace(pw_shell='/bin/bash')

    def admission(self):
        return self.h.preflight('operator', self.shadow, lambda _: self.account, today=20000)

    def test_valid_existing_password_does_not_change_any_files(self):
        keys = self.root / 'authorized_keys'; keys.write_text('TEST_KEY_SENTINEL\n')
        original = self.shadow.read_bytes(), keys.read_bytes()
        self.assertTrue(self.admission())
        self.assertEqual(original, (self.shadow.read_bytes(), keys.read_bytes()))

    def test_locked_empty_and_placeholder_passwords_refused(self):
        for password in ('', '!', '*', '!!', '!$y$locked', 'not-a-password'):
            with self.subTest(password_kind=len(password)):
                row = self.row.replace('$y$test_ephemeral_not_a_password_hash', password)
                with self.assertRaises(self.h.Failure): self.h.password_state(row, 20000)

    def test_error_never_contains_password_record(self):
        canary = '!SECRET_CANARY_NEVER_DISPLAY'
        try: self.h.password_state(self.row.replace('$y$test_ephemeral_not_a_password_hash', canary), 20000)
        except self.h.Failure as exc: self.assertNotIn(canary, str(exc))
        else: self.fail('locked record admitted')

    def test_password_change_required_refused(self):
        with self.assertRaisesRegex(self.h.Failure, 'CHANGE_REQUIRED'):
            self.h.password_state(self.row.replace(':19000:', ':0:'), 20000)

    def test_account_expiry_refused(self):
        with self.assertRaisesRegex(self.h.Failure, 'ACCOUNT_EXPIRED'):
            self.h.password_state(self.row.rstrip().rsplit(':', 2)[0] + ':19999:\n', 20000)

    def test_password_expiry_refused(self):
        with self.assertRaisesRegex(self.h.Failure, 'PASSWORD_EXPIRED'):
            self.h.password_state(self.row.replace(':99999:', ':30:'), 20000)

    def test_clock_regression_refused(self):
        with self.assertRaisesRegex(self.h.Failure, 'DATE_IN_FUTURE'):
            self.h.password_state(self.row, 18000)

    def test_malformed_shadow_numeric_values_refused(self):
        for value in ('NaN', '-2', '1.5'):
            with self.subTest(value=value), self.assertRaises(self.h.Failure):
                self.h.password_state(self.row.replace(':99999:', ':'+value+':'), 20000)

    def test_no_expiration_supported(self):
        self.assertTrue(self.h.password_state(self.row.replace(':99999:', '::'), 20000))

    def test_missing_account_or_duplicate_shadow_record_refused(self):
        with self.assertRaisesRegex(self.h.Failure, 'ACCOUNT_MISSING'):
            self.h.preflight('operator', self.shadow, lambda _: (_ for _ in ()).throw(KeyError()), today=20000)
        self.shadow.write_text(self.row * 2)
        with self.assertRaisesRegex(self.h.Failure, 'DUPLICATE'): self.admission()
        self.shadow.write_text(self.row.replace('operator:', 'other:'))
        with self.assertRaisesRegex(self.h.Failure, 'RECORD_MISSING'): self.admission()

    def test_nologin_shell_refused(self):
        for shell in ('/usr/sbin/nologin', '/bin/false', '/missing-shell', 'bash'):
            self.account.pw_shell = shell
            with self.subTest(shell=shell), self.assertRaises(self.h.Failure): self.admission()

    def test_shadow_symlink_refused(self):
        target = self.root / 'other'; self.shadow.rename(target); self.shadow.symlink_to(target)
        with self.assertRaises(OSError): self.admission()

    def test_shadow_fifo_does_not_block(self):
        self.shadow.unlink(); os.mkfifo(self.shadow, 0o600)
        with self.assertRaisesRegex(self.h.Failure, 'UNSAFE'): self.admission()

    def test_shadow_group_writable_refused(self):
        self.shadow.chmod(0o620)
        with self.assertRaisesRegex(self.h.Failure, 'UNSAFE'): self.admission()

    def test_invalid_administrator_name_refused(self):
        for user in ('', 'root\nOther', '../root', '-root'):
            with self.subTest(user=user), self.assertRaises(self.h.Failure):
                self.h.preflight(user, self.shadow, today=20000)

    def test_effective_password_only_exact_policy(self):
        text = '\n'.join(k+' '+v for k,v in self.h.EXPECTED.items())
        self.assertTrue(self.h.validate_effective(text))
        for key in self.h.EXPECTED:
            with self.subTest(key=key), self.assertRaises(self.h.Failure):
                self.h.validate_effective(text.replace(key+' '+self.h.EXPECTED[key], key+' WRONG'))

    def test_duplicate_effective_field_refused(self):
        text = '\n'.join(k+' '+v for k,v in self.h.EXPECTED.items())
        with self.assertRaisesRegex(self.h.Failure, 'DUPLICATE'):
            self.h.validate_effective(text+'\npubkeyauthentication yes')

    def test_failed_effective_command_not_success(self):
        with self.assertRaisesRegex(self.h.Failure, 'UNAVAILABLE'):
            self.h.check(lambda *a, **k: subprocess.CompletedProcess(a, 1, 'partial', 'SECRET_CANARY'))

    def test_three_prompts_and_no_fourth_password_prompt(self):
        # The three operator reads are fixed; the guard never consumes stdin/getpass.
        prompt_reads = re.findall(r'IFS= read -r -u "\$VK_TTY_FD" (VK_INPUT_\w+)', SCRIPT)
        self.assertEqual(prompt_reads, ['VK_INPUT_SECRET', 'VK_INPUT_DOMAIN', 'VK_INPUT_PANEL_IP'])
        code = payload('VK_SSH_GUARD_PY')
        for token in ('input(', 'getpass', 'chpasswd', 'usermod', 'authorized_keys.unlink'):
            self.assertNotIn(token, code)
        self.assertIn('PubkeyAuthentication no', payload('PY_SSH_CONFIG'))

    def test_ssh_candidate_validated_before_atomic_publication(self):
        code = payload('PY_SSH_CONFIG')
        self.assertLess(code.index("['/usr/sbin/sshd', '-t'"), code.index('tmp.replace(path)'))
        self.assertLess(code.index("['/usr/sbin/sshd', '-T'"), code.index('tmp.replace(path)'))
        self.assertIn('os.fsync', code)
        self.assertIn('SSH Match/Allow/Deny', SCRIPT)
        self.assertIn('SSH Include', SCRIPT)

    def test_generation_does_not_depend_on_preserved_key_policy(self):
        self.assertNotIn('PUBKEY_BEFORE', SCRIPT)
        self.assertIn('AuthenticationMethods password', SCRIPT)
        self.assertIn("'pubkeyauthentication no'", SCRIPT)
        self.assertIn('network-rollback-armed', SCRIPT)

class SshGraph230Tests(unittest.TestCase):
    def setUp(self):
        self.h=module('VK_SSH_GUARD_PY')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.main=self.root/'sshd_config'
        self.drop=self.root/'sshd_config.d';self.drop.mkdir()
        self.main.write_text('Include '+str(self.drop/'*.conf')+'\nPasswordAuthentication yes\n')
        self.main.chmod(0o600)

    def test_standard_distro_include_is_supported(self):
        (self.drop/'cloud.conf').write_text('# Match is only a comment\nPubkeyAuthentication yes\n')
        self.assertTrue(self.h.inspect_policy(self.main))

    def test_match_equal_syntax_cannot_override_keys(self):
        for directive in ('Match User root', 'Match=User root', 'mAtCh = Address *', 'AllowUsers=root'):
            (self.drop/'custom.conf').write_text(directive+'\nPubkeyAuthentication yes\n')
            with self.subTest(directive=directive),self.assertRaisesRegex(self.h.Failure,'REQUIRES_REVIEW'):
                self.h.inspect_policy(self.main)

    def test_nested_include_and_untrusted_directory_refused(self):
        f=self.drop/'nested.conf';f.write_text('Include '+str(self.drop/'*.conf'))
        with self.assertRaisesRegex(self.h.Failure,'RECURSIVE'):self.h.inspect_policy(self.main)
        f.unlink();self.drop.chmod(0o777)
        with self.assertRaisesRegex(self.h.Failure,'DIRECTORY_UNSAFE'):self.h.inspect_policy(self.main)

    def test_unsupported_custom_include_not_deleted(self):
        self.main.write_text('Include /srv/operator-ssh.conf\n')
        before=self.main.read_bytes()
        with self.assertRaisesRegex(self.h.Failure,'CUSTOM'):self.h.inspect_policy(self.main)
        self.assertEqual(before,self.main.read_bytes())

    def test_symlink_include_and_fifo_refused_without_hang(self):
        p=self.drop/'bad.conf';p.symlink_to(self.main)
        with self.assertRaises(OSError):self.h.inspect_policy(self.main)
        p.unlink();os.mkfifo(p,0o600)
        with self.assertRaises(self.h.Failure):self.h.inspect_policy(self.main)

class SshCandidate230Tests(unittest.TestCase):
    def setUp(self):
        self.h=module('PY_SSH_CONFIG');self.policy=module('VK_SSH_GUARD_PY')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.config=self.root/'sshd_config'
        self.original='Port 222\n# keep provider comment\nPubkeyAuthentication yes\n'
        self.config.write_text(self.original);self.config.chmod(0o600)
        self.ports=self.root/'ssh-ports';self.ports.write_text('222\n')
        self.keys=self.root/'authorized_keys';self.keys.write_bytes(b'PRESERVE_TEST_AUTHORIZED_KEYS')
        self.sequence=[]

    def candidate(self, failure=None):
        effective='\n'.join(k+' '+v for k,v in self.policy.EXPECTED.items())+'\nport 222\n'
        def paths(value):
            if value=='/etc/ssh/sshd_config':return self.config
            if value=='/etc/vkarmani-node/ssh-ports':return self.ports
            return Path(value)
        def output(args, **kw):
            self.sequence.append(args)
            if '-f' not in args:return 'port 222\npubkeyauthentication yes\n'
            self.assertEqual(self.config.read_text(),self.original)
            self.assertIn('PubkeyAuthentication no',Path(args[-1]).read_text())
            return effective.replace('pubkeyauthentication no','pubkeyauthentication yes') if failure=='effective' else effective
        def syntax(args, **kw):
            self.sequence.append(args)
            self.assertEqual(self.config.read_text(),self.original)
            if failure=='syntax':raise subprocess.CalledProcessError(1,args)
            return subprocess.CompletedProcess(args,0)
        with patch.object(self.h,'Path',side_effect=paths),patch.object(self.h.subprocess,'run',side_effect=syntax),patch.object(self.h.subprocess,'check_output',side_effect=output):
            self.h.main()

    def test_candidate_validated_then_published_and_keys_preserved(self):
        self.candidate()
        text=self.config.read_text()
        self.assertIn('AuthenticationMethods password\n',text)
        self.assertIn('PubkeyAuthentication no\n',text)
        self.assertTrue(text.endswith(self.original))
        self.assertEqual(self.keys.read_bytes(),b'PRESERVE_TEST_AUTHORIZED_KEYS')
        self.assertEqual(self.config.stat().st_mode&0o777,0o600)
        self.assertFalse(list(self.root.glob('.sshd_config.vkarmani.*')))

    def test_failed_syntax_does_not_publish_candidate(self):
        with self.assertRaises(subprocess.CalledProcessError):self.candidate('syntax')
        self.assertEqual(self.config.read_text(),self.original)
        self.assertFalse(list(self.root.glob('.sshd_config.vkarmani.*')))

    def test_ineffective_key_disable_does_not_publish(self):
        with self.assertRaisesRegex(ValueError,'not effective'):self.candidate('effective')
        self.assertEqual(self.config.read_text(),self.original)
        self.assertFalse(list(self.root.glob('.sshd_config.vkarmani.*')))

    def test_existing_unsafe_config_not_replaced(self):
        self.config.chmod(0o666)
        with self.assertRaisesRegex(ValueError,'unsafe sshd_config'):self.candidate()
        self.assertEqual(self.config.read_text(),self.original)

    def test_ssh_fifo_rejected_without_waiting_or_replacement(self):
        self.config.unlink();os.mkfifo(self.config,0o600)
        with self.assertRaisesRegex(ValueError,'unsafe sshd_config'):self.candidate()
        self.assertTrue(self.config.exists())

    def test_symlink_config_refused_and_target_preserved(self):
        target=self.root/'provider-config';self.config.rename(target);self.config.symlink_to(target)
        with self.assertRaises(OSError):self.candidate()
        self.assertEqual(target.read_text(),self.original)
