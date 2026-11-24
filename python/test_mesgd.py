import os
import sys
import json
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from pki import PKI

FIXTURES = os.path.join(os.path.dirname(__file__), '..', 'fixtures')
JWKS_FILE = os.path.join(FIXTURES, 'jwks.json')
ALICE = os.path.join(FIXTURES, 'test_mesgd_alice.json')
BOB = os.path.join(FIXTURES, 'test_mesgd_bob.json')


class TestMesgdProtocol(unittest.TestCase):
    """Client-side protocol: register JWKs, encrypt to a peer, verify signatures."""

    def tearDown(self):
        for path in (ALICE, BOB):
            if os.path.exists(path):
                os.remove(path)
        PKI.init(JWKS_FILE)

    def test_two_party_encrypt(self):
        PKI.generate(ALICE)
        alice_pub = PKI.pub_jwk()
        PKI.generate(BOB)
        ct = PKI.encrypt_with(alice_pub, 'secret from bob')
        PKI.init(ALICE)
        self.assertEqual(PKI.decrypt(ct), 'secret from bob')

    def test_signed_encrypted_message(self):
        PKI.generate(ALICE)
        alice_pub = PKI.pub_jwk()
        PKI.generate(BOB)
        plain = 'ping'
        sig = PKI.sign(plain)
        envelope = json.dumps(
            {'payload': plain, 'signature': sig}, separators=(',', ':'))
        ct = PKI.encrypt_with(alice_pub, envelope)
        PKI.init(ALICE)
        opened = json.loads(PKI.decrypt(ct))
        self.assertEqual(opened['payload'], plain)
        self.assertFalse(PKI.check_with_pub(alice_pub, opened['payload'], opened['signature']))
        PKI.init(BOB)
        self.assertTrue(PKI.check(plain, sig))

    def test_compact_register_envelope(self):
        PKI.init(JWKS_FILE)
        mesgd_pub = PKI.pub_jwk()
        PKI.generate(ALICE)
        payload = json.dumps({'name': 'alice'}, separators=(',', ':'))
        envelope = json.dumps(
            {'payload': payload, 'signature': PKI.sign(payload)},
            separators=(',', ':'))
        ct = PKI.encrypt_with(mesgd_pub, envelope)
        alice_pub = PKI.pub_jwk()
        PKI.init(JWKS_FILE)
        opened = json.loads(PKI.decrypt(ct))
        self.assertEqual(json.loads(opened['payload'])['name'], 'alice')
        self.assertTrue(PKI.check_with_pub(alice_pub, opened['payload'], opened['signature']))

    @unittest.skipUnless(os.environ.get('MESGD_URL'), 'set MESGD_URL for live mesgd')
    def test_live_register_auth_message(self):
        self.skipTest('mesgd HTTP JWK registration is not wired yet')


if __name__ == '__main__':
    unittest.main()
