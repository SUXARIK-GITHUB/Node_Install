"""Deletion must not occur as a side effect of the menu or an inventory."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import removal_plan as rp


class RemovalTests(unittest.TestCase):
    def test_clean_host_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            answer=rp.plan(Path(temp),expected_uid=os.geteuid())
            self.assertEqual(answer['status'],'NOT_OWNED')
            self.assertFalse(answer['owned'])
            self.assertEqual(answer['full_removal'],'REQUIRES_VERIFIED_PROVIDER_SNAPSHOT_RESTORE')

    def test_partial_checkpoint_and_strict_backup(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp)/'var/lib/vkarmani-node'
            state.mkdir(parents=True,mode=0o700)
            (state/'owned-installation').write_text('')
            (state/'INSTALL_FAILED').write_text('rc=1')
            (state/'network-rollback-armed').write_text('')
            answer=rp.plan(Path(temp),expected_uid=os.geteuid())
            self.assertEqual(answer['status'],'PARTIAL_INSTALLATION')
            self.assertEqual(answer['backup'],'NOT_VERIFIED')
            self.assertEqual(answer['recovery'],'NARROW_SSH_UFW_ROLLBACK_AVAILABLE')
            (state/'INSTALL_COMPLETE').write_text('version=2.5.18')
            self.assertEqual(rp.plan(Path(temp),expected_uid=os.geteuid())['status'],'COMPLETE_NODE')
            (state/'INSTALL_COMPLETE').unlink()
            (state/'INSTALL_FAILED').unlink()
            (state/'INSTALL_FAILED').symlink_to('/etc/passwd')
            self.assertEqual(rp.plan(Path(temp),expected_uid=os.geteuid())['status'],'STOP_UNSAFE_SYMLINK')

    def test_no_unconditional_rollback(self):
        with mock.patch.object(rp.os,'geteuid',return_value=1000):
            result=rp.narrow_network_recovery(inspector=lambda:{'status':'PARTIAL_INSTALLATION','recovery':'NARROW_SSH_UFW_ROLLBACK_AVAILABLE'})
        self.assertEqual(result['status'],'STOP')


if __name__=='__main__':unittest.main()
