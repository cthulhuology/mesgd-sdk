import json
import unittest
from pathlib import Path
from auth import AuthClient, AuthError, https_transport

class AuthTests(unittest.TestCase):
    def test_contract(self):
        cases=json.loads((Path(__file__).parent/'../fixtures/auth_contract.json').read_text())
        for row in cases:
            with self.subTest(operation=row['op']):
                def transport(m,p,b,t):
                    self.assertEqual([m,p,b,t],[row['method'],row['path'],row['body'],row['token']])
                    return 200,row['result']
                self.assertEqual(getattr(AuthClient(transport),row['op'])(*row['args']),row['result'])
    def test_rejections(self):
        def never(*a): self.fail('invalid input reached transport')
        a=AuthClient(never)
        for otp in [12345,123456,'12345','1234567','01234x','012345\n','１２３４５６']:
            with self.assertRaises((ValueError,TypeError)): a.login('u','p',otp)
        for f in ['d','p','q','dp','dq','qi','oth','k']:
            with self.assertRaises(ValueError): a.signup('u','e','p',[{f:'PRIVATE'}])
        with self.assertRaises(ValueError): https_transport('http://localhost')
        with self.assertRaises(ValueError): https_transport('https://user:password@example.com')
    def test_errors_redact_body(self):
        a=AuthClient(lambda *a:(401,{'secret':'DO_NOT_LOG'}))
        with self.assertRaises(AuthError) as e: a.login('u','p','012345')
        self.assertEqual(e.exception.status,401)
        self.assertNotIn('DO_NOT_LOG',str(e.exception))

if __name__=='__main__': unittest.main()
