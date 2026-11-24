"""Transport framing tests (no server): plain / signed / sealed frame building
and decode+dispatch, exercising the seal/open path."""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from pki import PKI
from mesgd import Mesgd

JWKS_FILE = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'jwks.json')


class TransportFramingTest(unittest.TestCase):
    def setUp(self):
        PKI.init(JWKS_FILE)
        # a Mesgd whose socket is never used; we drive _frame/_dispatch directly
        self.conn = Mesgd(None, PKI, PKI.pub_jwk())

    def test_plain_frame(self):
        wire = json.loads(self.conn._frame(
            {'to': 'x/y', 'type': 'ping', 'body': {'a': 1}}, False, False))
        self.assertIn('body', wire)
        self.assertNotIn('enc', wire)
        self.assertNotIn('sig', wire)

    def test_signed_sealed_roundtrip(self):
        wire_str = self.conn._frame(
            {'to': 'agents/alice/inbox', 'type': 'task.request',
             'body': {'cap': 'summarize', 'n': 3}}, True, True)
        wire = json.loads(wire_str)
        self.assertIn('enc', wire)                 # sealed
        self.assertNotIn('body', wire)             # body hidden
        self.assertEqual(wire['to'], 'agents/alice/inbox')  # routable cleartext
        self.assertIn('sig', wire)

        got = {}
        self.conn.on('task.request', lambda m: got.update(m))
        self.conn._dispatch(wire_str)
        self.assertEqual(got['type'], 'task.request')
        self.assertEqual(got['body']['cap'], 'summarize')   # sealed body recovered
        self.assertTrue(PKI.check_with_pub(
            PKI.pub_jwk(), json.dumps(got['body']), got['sig']))  # sig over body


if __name__ == '__main__':
    unittest.main()
