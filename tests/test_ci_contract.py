"""Regression checks for CI setup and test isolation, not a live Actions runner."""
import unittest

import yaml
from common import ROOT


class CIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.safe_load((ROOT / '.github/workflows/check.yml').read_text())

    def test_ubuntu_26_dependencies_including_git_precede_checkout(self):
        steps = self.workflow['jobs']['ubuntu-26-userspace']['steps']
        checkout = next(i for i, step in enumerate(steps)
                        if step.get('uses', '').startswith('actions/checkout@'))
        installs = [step['run'] for step in steps[:checkout]
                    if 'apt-get install' in step.get('run', '')]
        self.assertEqual(len(installs), 1)
        line = next(line for line in installs[0].splitlines() if 'apt-get install' in line)
        self.assertIn('git', line.split())
        self.assertIn('ca-certificates', line.split())

    def test_required_os_matrix_and_container_are_preserved(self):
        jobs = self.workflow['jobs']
        self.assertEqual(jobs['test']['strategy']['matrix']['os'], ['ubuntu-22.04', 'ubuntu-24.04'])
        self.assertIs(jobs['test']['strategy']['fail-fast'], False)
        self.assertEqual(jobs['ubuntu-26-userspace']['container'], 'ubuntu:26.04')
        self.assertEqual(jobs['ubuntu-26-userspace']['runs-on'], 'ubuntu-24.04')

    def test_checkout_and_checksums_verified_before_tests(self):
        for job in self.workflow['jobs'].values():
            with self.subTest(job=job['runs-on']):
                steps = job['steps']
                tests = next(i for i, s in enumerate(steps) if 'bash tests/run.sh' in s.get('run', ''))
                before = '\n'.join(s.get('run', '') for s in steps[:tests])
                self.assertIn('git rev-parse --is-inside-work-tree', before)
                self.assertIn('sha256sum --check SHA256SUMS', before)
                self.assertNotIn('git diff', steps[tests]['run'])
                self.assertIn('git diff --check', '\n'.join(s.get('run', '') for s in steps[tests + 1:]))

    def test_tests_stay_unprivileged_on_vm_and_failures_are_not_ignored(self):
        self.assertEqual(self.workflow['permissions'], {'contents': 'read'})
        self.assertEqual(self.workflow['defaults']['run']['shell'], 'bash')
        for job in self.workflow['jobs'].values():
            self.assertNotIn('continue-on-error', job)
            for step in job['steps']:
                self.assertNotIn('continue-on-error', step)
                run = step.get('run', '')
                self.assertNotRegex(run, r'sudo\s+(?:-\S+\s+)*bash\s+tests/run\.sh')
                self.assertNotRegex(run, r'bash\s+(?:\./)?install\.sh')
                self.assertNotIn('|| true', run)
                if 'uses' in step:
                    self.assertRegex(step['uses'], r'@(?:[0-9a-f]{40})$')
                    self.assertIs(step['with']['persist-credentials'], False)

    def test_manifest_text_files_are_git_canonical_lf(self):
        manifest = (ROOT / 'SHA256SUMS').read_text().splitlines()
        bad = []
        for line in manifest:
            if not line.strip():
                continue
            _, rel = line.split('  ', 1)
            data = (ROOT / rel).read_bytes()
            if b'\x00' in data:
                continue
            try:
                data.decode('utf-8')
            except UnicodeDecodeError:
                continue
            if b'\r' in data:
                bad.append(rel)
        self.assertEqual(bad, [], 'manifest text must be LF-canonical for Git checkout')

    def test_nginx_fixture_redirects_all_compiled_temp_defaults(self):
        text = (ROOT / 'tests/test_tls_integration.py').read_text()
        for directive in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
            self.assertIn("('" + directive + "',", text)
        self.assertIn('{directive}_temp_path {cls.root}/temp/{directory}', text)


if __name__ == '__main__':
    unittest.main()
