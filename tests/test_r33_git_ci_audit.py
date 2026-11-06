"""Git CI clean-worktree guard tests: isolated local Git, no network or VPS mutations."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml
from common import ROOT


class GitCICleanTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs=yaml.safe_load((ROOT/'.github/workflows/check.yml').read_text())['jobs']

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='node-git-ci-r33-')
        self.addCleanup(self.tmp.cleanup)
        self.repo=Path(self.tmp.name)/'checkout'
        self.repo.mkdir()
        self.env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        self.env['GIT_CONFIG_NOSYSTEM']='1'
        self.env['GIT_CONFIG_GLOBAL']=os.devnull
        self.env['GIT_TERMINAL_PROMPT']='0'
        self.call(['git','init','-q','-b','main'])
        (self.repo/'README.md').write_text('original\n')
        self.call(['git','add','README.md'])
        self.call(['git','-c','user.name=Test','-c','user.email=test@example.invalid',
                   'commit','-q','-m','fixture'])

    def call(self,args,*,expected=0):
        r=subprocess.run(args,cwd=self.repo,env=self.env,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,text=True,timeout=10)
        self.assertEqual(r.returncode,expected,repr((args,r.stdout,r.stderr)))
        return r

    def audit(self,job='test',*,expected=0):
        steps=self.jobs[job]['steps']
        clean=next(s['run'] for s in steps if 'git diff --exit-code' in s.get('run',''))
        return self.call(['bash','-euo','pipefail','-c',clean],expected=expected)

    def test_all_github_jobs_have_guard_after_tests(self):
        self.assertEqual(set(self.jobs),{'test','ubuntu-26-userspace','debian-userspace'})
        for name,job in self.jobs.items():
            with self.subTest(name=name):
                steps=job['steps']
                t=next(i for i,s in enumerate(steps) if 'bash tests/run.sh' in s.get('run',''))
                check=next(i for i,s in enumerate(steps) if 'git diff --exit-code' in s.get('run',''))
                self.assertGreater(check,t)
                run=steps[check]['run']
                self.assertIn('git diff --check',run)
                self.assertIn('git status --porcelain=v1 --untracked-files=all',run)
                self.assertNotIn('git reset',run)
                self.assertNotIn('git clean',run)
                self.assertIn('exit 1',run)

    def test_clean_worktree_passes(self):
        for name in self.jobs:
            with self.subTest(job=name):self.audit(name)

    def test_untracked_file_not_silently_accepted(self):
        p=self.repo/'NEW_IGNORED_BY_OLD_DIFF.txt';p.write_text('untracked\n')
        self.call(['git','diff','--exit-code']) # old check silently passed
        for name in self.jobs:
            with self.subTest(job=name):
                r=self.audit(name,expected=1)
                self.assertIn(p.name,r.stderr)
        self.assertTrue(p.exists()) # guard is not destructive

    def test_staged_only_change_not_silently_accepted(self):
        p=self.repo/'README.md';p.write_text('staged-only\n')
        self.call(['git','add','README.md'])
        self.call(['git','diff','--exit-code']) # old check silently passed
        for name in self.jobs:
            with self.subTest(job=name):
                r=self.audit(name,expected=1)
                self.assertIn('README.md',r.stderr)
        self.assertEqual(p.read_text(),'staged-only\n')

    def test_unstaged_change_rejected_and_preserved(self):
        p=self.repo/'README.md';p.write_text('unstaged\n')
        for name in self.jobs:
            with self.subTest(job=name):self.audit(name,expected=1)
        self.assertEqual(p.read_text(),'unstaged\n')

    def test_untracked_dotenv_stays_ignored_but_not_deleted(self):
        p=self.repo/'.env';p.write_text('TEST_SECRET=fixture\n')
        # In the real project .gitignore ignores .env. Mirror that restriction.
        (self.repo/'.gitignore').write_text('.env\n')
        self.call(['git','add','.gitignore'])
        self.call(['git','-c','user.name=Test','-c','user.email=test@example.invalid',
                   'commit','-q','-m','ignore-test'])
        self.audit()
        self.assertTrue(p.exists())


if __name__=='__main__':unittest.main()
