"""Protect historical 2.5.6/2.5.9 contract bytes and review r4 exceptions.

Original hashes stay recorded below, not silently discarded. R4 explicitly changed
only RKN checkpoint reporting and GitHub's test-matrix YAML, with semantic tests
in test_2510_r4_preparation.py; every unaffected SHA256 guard is still in force.
"""
import hashlib
import unittest
from common import ROOT, SCRIPT, payload

PAYLOADS = {
    'VK_PAYLOAD_VK_WRITE_TLS_CHECK': '831f03f01d9a8358db413c4fa3a95f5f8a3e04cb01a7264f77c4ec99c53947c6',
    'VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK': '164d9470afb93849f6439bad6dc7672cca667e55477ba7bf009426a6fe86beab',
    'VK_PAYLOAD_VK_WRITE_NETWORK_UNIT': '5741b7a7e1890683f4d0c0d1bc17609fbabdc9d71cdf654b88a3e47da142dd54',
    'VK_PAYLOAD_VK_WRITE_NGINX_DROPIN': 'a58d43d99d8d3dde7e2f0dfd6f042d4dbe247171ee5a2a5f5dfcdff73bb4cacf',
    'VK_CERT_DEPLOY_PY': '0351ad1008fbff4297549c74aac4a47c6db9991b63b82a23990106a3030f0c7d',
    'VK_RKN_GUARD_PY': '6ee94729acb61e54c831b6f5539d75b8a3029411b9dfefb6d432f01bfdff425d',
    'VK_RKN_COMPILE': 'f409db5442884d00859ac56ee661a25188f2041bb0c66ac170d5f931e418da0e',
    'VK_RKN_WRAPPER': 'd41efb951f90d1d2eba5926d90aab0e1d612dd73cd49e007f8338c2f397ca664',
    'VK_RKN_PREPARE_UNIT': '6d8e88ae67955961f2589beb334e433c3a8cddde29630f0cd2e8386e62023cb3',
    'VK_RKN_UPDATE_UNIT': 'ce9742dd34f4e86c5ce73e9b3ca34b3e5645df5725e3dd4e78fffc5ef6e00525',
    'VK_RKN_UPDATE_TIMER': '04e4919620c11a2f7b5ab179c0c3f5d25623fea28fc2271f310fa6a350003268',
    'VK_RKN_UFW_DEP': 'de12fad09943a0abebdab72fe1071b6abb926680046f9e26b85b5fe89793ca60',
    'PY_NGINX_MAIN': '851d93085f915475247bf88c651e6fc9d2fd46b7821d7b5e7a7f46ed62b457f0',
}
FILES = {
    'integrations/rkn_guard.py': '6ee94729acb61e54c831b6f5539d75b8a3029411b9dfefb6d432f01bfdff425d',
    'integrations/xhttp_profile.py': 'dfbd7de45c65695d43d1b033f481978489b3ea15144cab944ce5a923cc0f2d20',
    'integrations/xray_versions.py': '244b15d369e8658202b05dfc55f286608d2ae0eb0fe6c0f5538a6005a3cd0ede',
    'examples/inbound-raw-full.example.json': 'e967d9d8eafcb7738c52882eb6c05d9b281242a671b36e759d5d9f709e6cd10e',
    'examples/inbound-xhttp-full.example.json': '074a792c147831ff73f35531ad4934db0f6de30bcc3c48955c7c4c633e7b6586',
    '.github/workflows/check.yml': 'b438d42132f00e315d426f6a4009559b16012c23397c2c2456d46d7b6454c2f0',
}


# Reviewed r4 changes ONLY; previous expected hashes remain intact in the
# baseline dictionaries above. Intentional changes: distinguish RKN list
# checks from content changes, and include Debian CI jobs. No other overrides.
R4_APPROVED_PAYLOAD_SHA256 = {
    'VK_RKN_GUARD_PY': 'd9239fb216bf8de3d89c2945cc100a3099516e588ba490b8caa497a004161664',
}
R4_APPROVED_FILE_SHA256 = {
    'integrations/rkn_guard.py': 'd9239fb216bf8de3d89c2945cc100a3099516e588ba490b8caa497a004161664',
    '.github/workflows/check.yml': 'd7913822fcf750e8d95e452ff90113a8ebef3ddd6add44b839c85ca5a4f90aea',
}

# Reviewed r6 change: on cascade Exit, the immutable Entry peer IPv4 joins
# the RKN trusted ipset for public 80/443. Ordinary and Entry remain unchanged;
# Node API management ACL still uses ONLY panel_ipv4. Historical hashes kept.
R6_APPROVED_PAYLOAD_SHA256 = {
    'VK_RKN_GUARD_PY': '57a4e9a2840ee6b1c17ebed1192cc48154a21def201087974cb3dce7a473147d',
}
R6_APPROVED_FILE_SHA256 = {
    'integrations/rkn_guard.py': '57a4e9a2840ee6b1c17ebed1192cc48154a21def201087974cb3dce7a473147d',
}

class PreservedPolicy256(unittest.TestCase):
    def test_reviewed_network_and_cover_payloads_unchanged(self):
        for tag, expected in PAYLOADS.items():
            with self.subTest(tag=tag):
                expected_for_this_candidate = R6_APPROVED_PAYLOAD_SHA256.get(tag, R4_APPROVED_PAYLOAD_SHA256.get(tag, expected))
                self.assertEqual(hashlib.sha256(payload(tag).encode()).hexdigest(), expected_for_this_candidate)

    def test_existing_integrations_and_full_profile_examples_unchanged(self):
        for name, expected in FILES.items():
            with self.subTest(name=name):
                expected_for_this_candidate = R6_APPROVED_FILE_SHA256.get(name, R4_APPROVED_FILE_SHA256.get(name, expected))
                self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(), expected_for_this_candidate)

    def test_reviewed_r4_hash_overrides_are_explicit_and_keep_prior_baselines(self):
        self.assertEqual(set(R4_APPROVED_PAYLOAD_SHA256), {'VK_RKN_GUARD_PY'})
        self.assertEqual(set(R4_APPROVED_FILE_SHA256),
                         {'integrations/rkn_guard.py', '.github/workflows/check.yml'})
        self.assertEqual(R4_APPROVED_PAYLOAD_SHA256['VK_RKN_GUARD_PY'],
                         R4_APPROVED_FILE_SHA256['integrations/rkn_guard.py'])
        for name, new in R4_APPROVED_PAYLOAD_SHA256.items():
            self.assertNotEqual(new, PAYLOADS[name])
        for name, new in R4_APPROVED_FILE_SHA256.items():
            self.assertNotEqual(new, FILES[name])

    def test_reviewed_r6_has_explicit_new_hash_and_preserves_r4_record(self):
        self.assertEqual(R6_APPROVED_FILE_SHA256['integrations/rkn_guard.py'],
                         R6_APPROVED_PAYLOAD_SHA256['VK_RKN_GUARD_PY'])
        self.assertNotEqual(R6_APPROVED_PAYLOAD_SHA256['VK_RKN_GUARD_PY'],
                            R4_APPROVED_PAYLOAD_SHA256['VK_RKN_GUARD_PY'])

    def test_finish_rkn_cannot_install_packages(self):
        self.assertIn('VK_RKN_NO_PACKAGE_INSTALL=1; source "$1";', payload('VK_FINALIZER_PY'))
        fn = SCRIPT.split('vk_rkn_activate() {', 1)[1].split('vkarmani_rkn_command()', 1)[0]
        self.assertLess(fn.index('VK_RKN_NO_PACKAGE_INSTALL'), fn.index('apt-get -o'))
        self.assertIn("echo 'RKN: ipset missing; finish-only mode never installs packages.'", fn)

    def test_no_live_node_identity_in_new_finalizer(self):
        text = payload('VK_FINALIZER_PY')
        for forbidden in ('spite.vkarmani.com', '13.143.239.100', '80.66.81.68'):
            self.assertNotIn(forbidden,text)
