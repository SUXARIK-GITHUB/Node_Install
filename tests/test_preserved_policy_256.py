"""Protect reviewed network/cover/profile policy against incidental NTP hotfix edits.
Hashes are from release 2.5.5 source commit 8780852ac1adc15293758aae2d8ce1b7584b0380.
"""
import hashlib
import unittest
from common import ROOT, SCRIPT, payload

PAYLOADS = {
    'VK_PAYLOAD_VK_WRITE_TLS_CHECK': '831f03f01d9a8358db413c4fa3a95f5f8a3e04cb01a7264f77c4ec99c53947c6',
    'VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK': '8cd3c88a79614c70e76b71c5c3d44a935f6f83ef97150aa0d6550b1b021db509',
    'VK_PAYLOAD_VK_WRITE_NETWORK_UNIT': '5741b7a7e1890683f4d0c0d1bc17609fbabdc9d71cdf654b88a3e47da142dd54',
    'VK_PAYLOAD_VK_WRITE_NGINX_DROPIN': 'a58d43d99d8d3dde7e2f0dfd6f042d4dbe247171ee5a2a5f5dfcdff73bb4cacf',
    'VK_CERT_DEPLOY_PY': '0351ad1008fbff4297549c74aac4a47c6db9991b63b82a23990106a3030f0c7d',
    'VK_RKN_GUARD_PY': '89470f5b6c20a990757d64531483ffd7d0ca69095f6f6a44875fa819fbe982f7',
    'VK_RKN_COMPILE': 'f409db5442884d00859ac56ee661a25188f2041bb0c66ac170d5f931e418da0e',
    'VK_RKN_WRAPPER': 'd41efb951f90d1d2eba5926d90aab0e1d612dd73cd49e007f8338c2f397ca664',
    'VK_RKN_PREPARE_UNIT': '6d8e88ae67955961f2589beb334e433c3a8cddde29630f0cd2e8386e62023cb3',
    'VK_RKN_UPDATE_UNIT': 'ce9742dd34f4e86c5ce73e9b3ca34b3e5645df5725e3dd4e78fffc5ef6e00525',
    'VK_RKN_UPDATE_TIMER': '04e4919620c11a2f7b5ab179c0c3f5d25623fea28fc2271f310fa6a350003268',
    'VK_RKN_UFW_DEP': 'de12fad09943a0abebdab72fe1071b6abb926680046f9e26b85b5fe89793ca60',
    'PY_NGINX_MAIN': '851d93085f915475247bf88c651e6fc9d2fd46b7821d7b5e7a7f46ed62b457f0',
}
FILES = {
    'integrations/rkn_guard.py': '89470f5b6c20a990757d64531483ffd7d0ca69095f6f6a44875fa819fbe982f7',
    'integrations/xhttp_profile.py': 'dfbd7de45c65695d43d1b033f481978489b3ea15144cab944ce5a923cc0f2d20',
    'integrations/xray_versions.py': 'c5087fcd35c0a8bfefaccadf3ff6f79ac8adf8235d9b000c3d41c044fd04d8b0',
    'examples/inbound-raw-full.example.json': 'e967d9d8eafcb7738c52882eb6c05d9b281242a671b36e759d5d9f709e6cd10e',
    'examples/inbound-xhttp-full.example.json': '074a792c147831ff73f35531ad4934db0f6de30bcc3c48955c7c4c633e7b6586',
    '.github/workflows/check.yml': 'f02047981f2d6a49b9c14b3b6297fec10d52710450e46a8428e730f0a7fc8f52',
}

class PreservedPolicy256(unittest.TestCase):
    def test_reviewed_network_and_cover_payloads_unchanged(self):
        for tag, expected in PAYLOADS.items():
            with self.subTest(tag=tag):
                self.assertEqual(hashlib.sha256(payload(tag).encode()).hexdigest(), expected)

    def test_existing_integrations_and_full_profile_examples_unchanged(self):
        for name, expected in FILES.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(), expected)

    def test_finish_rkn_cannot_install_packages(self):
        self.assertIn('VK_RKN_NO_PACKAGE_INSTALL=1; source "$1";', payload('VK_FINALIZER_PY'))
        fn = SCRIPT.split('vk_rkn_activate() {', 1)[1].split('vkarmani_rkn_command()', 1)[0]
        self.assertLess(fn.index('VK_RKN_NO_PACKAGE_INSTALL'), fn.index('apt-get -o'))
        self.assertIn("echo 'RKN: ipset missing; finish-only mode never installs packages.'", fn)

    def test_no_live_node_identity_in_new_finalizer(self):
        text = payload('VK_FINALIZER_PY')
        for forbidden in ('spite.vkarmani.com', '13.143.239.100', '80.66.81.68'):
            self.assertNotIn(forbidden,text)
