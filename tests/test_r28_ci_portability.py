"""CI portability regressions: no host installation or external calls."""
import hashlib
from pathlib import Path
import sys
import unittest

from common import ROOT
sys.path.insert(0, str(ROOT/'scripts'))
import site_catalog as catalog


class CIPortability(unittest.TestCase):
    def test_generated_colors_and_unchanged_site_bytes(self):
        for dark in (False, True):
            spec = next(spec for spec in catalog.THEMES.values()
                        if (spec.layout in ('terminal','dashboard','gallery','luxury','museum')) == dark
                        and spec.name not in catalog.SIGNATURES)
            rendered = catalog.render(spec.name)
            expected = (ROOT/'site-catalog'/spec.name/'index.html').read_bytes()
            self.assertEqual(rendered['index.html'], expected)
            tag = b'<meta name="color-scheme" content="' + (b'dark' if dark else b'light') + b'">'
            self.assertIn(tag, rendered['index.html'])

    def test_compilation_is_early_and_does_not_create_cache(self):
        runner = (ROOT/'tests/run.sh').read_text()
        self.assertIn("compile(path.read_bytes(), str(path), 'exec')", runner)
        self.assertIn('PYTHON_SYNTAX=PASS', runner)
        self.assertIn('bash -n "$script"', runner)
        self.assertLess(runner.index('PYTHON_SYNTAX=PASS'), runner.index('for test_file in tests/test_*.py'))

    def test_nginx_fixtures_isolate_logs_not_production(self):
        fixture = (ROOT/'tests/test_r23_transport_network_visual.py').read_text()
        self.assertEqual(fixture.count('http { access_log off; server { '), 2)
        self.assertIn('test_actual_nginx_unix_tls_with_proxy_v1', fixture)
        self.assertIn('test_real_nginx_fragment_syntax_in_isolated_config', fixture)

    def test_xray_symlink_policy_remains_enforced(self):
        source = (ROOT/'integrations/transport_readiness.py').read_text()
        self.assertIn('p.is_symlink()', source)
        fixture = (ROOT/'tests/test_r26_runtime_gate.py').read_text()
        self.assertIn("root/'xray-test-stub'", fixture)
        self.assertNotIn("Path('/usr/bin/true')", fixture)


if __name__ == '__main__':
    unittest.main()
