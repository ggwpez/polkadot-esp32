import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import door

def leaf(key, value, hashed=False):
    n = 2*len(key)
    maximum = 31 if hashed else 63
    header = bytes([(0x20 if hashed else 0x40) | min(n,maximum)])
    if n >= maximum:
        n -= maximum
        while n >= 255:
            header += b'\xff'; n -= 255
        header += bytes([n])
    if hashed:
        return header + key + hashlib.blake2b(value,digest_size=32).digest()
    assert len(value)<64
    return header + key + bytes([len(value)*4]) + value

class ToolsTest(unittest.TestCase):
    def test_placeholder_deployment_requires_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'deployment.json'
            path.write_text('{"address":"0x' + '0' * 40 + '"}')
            with patch.object(door, 'DEPLOYMENT', path):
                with self.assertRaisesRegex(RuntimeError, 'deploy your own contract'):
                    door.address()

    def test_commitment_canonicalization_and_domain(self):
        with patch.dict(os.environ, {'DOOR_PEPPER_HEX':'01'*32,'DOOR_SALT_HEX':'02'*32}):
            self.assertEqual(door.commitment('alice'),door.commitment('04:00:00:00:00:00:01'))
            self.assertNotEqual(door.commitment('alice'),door.commitment('bob'))
            self.assertNotEqual(door.commitment('alice'),door.commitment('alice',bytes(32)))
            for bad in ('1234','04:00:00:00:00','xx:00:00:00'):
                with self.assertRaises(ValueError): door.commitment(bad)

    def test_two_leg_proof_and_hashed_policy_value(self):
        policy=b'DOR1'+bytes(388)
        child_key=b':child_storage:default:'+bytes(range(32))
        child_node=leaf(door.STORAGE_KEY,policy,True)
        child_root=hashlib.blake2b(child_node,digest_size=32).digest()
        top_node=leaf(child_key,child_root)
        root=hashlib.blake2b(top_node,digest_size=32).digest()
        proven_root=door.verify(root,child_key,[top_node.hex()])
        self.assertEqual(proven_root,child_root)
        self.assertEqual(door.verify(proven_root,door.STORAGE_KEY,[child_node.hex(),policy.hex()]),policy)
        for nodes in ([child_node.hex()], [child_node.hex(),(policy[:-1]+b'X').hex()], []):
            with self.assertRaises(RuntimeError): door.verify(proven_root,door.STORAGE_KEY,nodes)
        with self.assertRaises(RuntimeError): door.verify(bytes(32),child_key,[top_node.hex()])
        with self.assertRaises(RuntimeError): door.verify(root,child_key[:-1]+b'X',[top_node.hex()])

if __name__=='__main__': unittest.main()
