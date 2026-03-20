import os
import sys
import json
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from pki import PKI

FIXTURES    = os.path.join(os.path.dirname(__file__), '..', 'fixtures')
JWKS_FILE   = os.path.join(FIXTURES, 'jwks.json')
GEN_FILE    = os.path.join(FIXTURES, 'test_python.json')
SIG_OUT     = os.path.join(FIXTURES, 'sig_python.json')
CROSS_LANGS = ['erlang', 'javascript', 'ruby', 'rust', 'go', 'c']


class TestPKI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        PKI.init(JWKS_FILE)

    def test_sign_verify_roundtrip(self):
        sig = PKI.sign('Hello World')
        self.assertTrue(PKI.verify('Hello World', sig))
        self.assertFalse(PKI.verify('Wrong message', sig))

    def test_signature_is_json(self):
        sig = PKI.sign('Hello World')
        obj = json.loads(sig)
        self.assertIn('r', obj)
        self.assertIn('s', obj)

    def test_encrypt_decrypt_roundtrip(self):
        enc = PKI.encrypt('Secret message')
        self.assertEqual(PKI.decrypt(enc), 'Secret message')

    def test_generate_creates_json_file(self):
        if os.path.exists(GEN_FILE):
            os.remove(GEN_FILE)
        PKI.generate(GEN_FILE)
        self.assertTrue(os.path.exists(GEN_FILE))
        with open(GEN_FILE) as f:
            jwks = json.load(f)
        self.assertIsInstance(jwks, list)
        uses  = {(j['use'], j['key_ops'][0]) for j in jwks}
        self.assertIn(('sig', 'verify'),  uses)
        self.assertIn(('sig', 'sign'),    uses)
        self.assertIn(('enc', 'decrypt'), uses)
        self.assertIn(('enc', 'encrypt'), uses)

    def test_generated_keys_work(self):
        PKI.generate(GEN_FILE)
        PKI.init(GEN_FILE)
        sig = PKI.sign('Hello World')
        self.assertTrue(PKI.verify('Hello World', sig))
        enc = PKI.encrypt('Secret')
        self.assertEqual(PKI.decrypt(enc), 'Secret')
        # restore reference keys for cross-lang tests
        PKI.init(JWKS_FILE)

    def test_write_cross_lang_signature(self):
        PKI.init(JWKS_FILE)
        sig = PKI.sign('Hello World')
        with open(SIG_OUT, 'w') as f:
            json.dump({'lang': 'python', 'message': 'Hello World', 'signature': sig}, f)

    def test_verify_cross_lang_signatures(self):
        PKI.init(JWKS_FILE)
        for lang in CROSS_LANGS:
            path = os.path.join(FIXTURES, f'sig_{lang}.json')
            if not os.path.exists(path):
                continue
            with open(path) as f:
                rec = json.load(f)
            self.assertTrue(
                PKI.verify(rec['message'], rec['signature']),
                f"Failed to verify signature from {lang}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
