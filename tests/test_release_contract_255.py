"""2.5.5: backward-compatible completed-node gates and duplicate-free egress."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from common import SCRIPT, module, payload


class ReleaseContract255(unittest.TestCase):
    def test_completed_node_255_recognized_in_every_maintenance_path(self):
        self.assertIn("'version=2.5.4', 'version=2.5.5'", SCRIPT)
        self.assertIn("'2.5.4', '2.5.5'", SCRIPT)
        self.assertIn('"$version" == 2.5.4 || "$version" == 2.5.5', SCRIPT)
        self.assertIn("'^version=2\\.5\\.[23456]$'", SCRIPT)
        self.assertIn('"$INSTALL_VERSION" == 2.5.4 || "$INSTALL_VERSION" == 2.5.5',
                      payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE'))

    def test_generator_does_not_repeat_own_public_ipv4(self):
        helper = module('PY_HELPER')
        with tempfile.TemporaryDirectory(prefix='vk-255-route-') as tmp:
            helper.ETC = Path(tmp)
            helper.REALITY_EXPORT = Path(tmp) / 'keys.txt'
            config = {'domain':'node.example.test','public_ipv4':'8.8.4.4',
                      'panel_ipv4':['1.1.1.1'],'node_port':2222}
            with patch.object(helper, 'detect_local_public_ipv4s',
                              return_value={'8.8.4.4':'eth0'}):
                _, _, profile = helper.make_keys_profile(config)
            ip_list = profile['routing']['rules'][0]['ip']
            self.assertEqual(ip_list.count('8.8.4.4/32'), 1)
            self.assertEqual(ip_list.count('1.1.1.1/32'), 1)
            self.assertEqual(len(ip_list), len(set(ip_list)))

    def test_no_unsafe_auto_xray_binary_replacement(self):
        command = SCRIPT.split('--xray-versions) shift; vkarmani_xray_versions_main')[0]
        self.assertIn('XRAY_UPDATE_ACTION=NONE', command)
        self.assertIn('docker exec', command)
        self.assertNotIn('curl | bash', command)


if __name__ == '__main__':
    unittest.main()
