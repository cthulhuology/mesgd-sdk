import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers, rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers, SECP256R1
)


def _b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def _b64url_decode(s):
    s = s.encode() if isinstance(s, str) else s
    pad = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + b'=' * pad)

def _int_to_bytes(n, length=None):
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if length:
        b = b.rjust(length, b'\x00')
    return b

def _bytes_to_int(b):
    return int.from_bytes(_b64url_decode(b) if isinstance(b, str) else b, 'big')


class PKI:
    FILE = 'pki_keys.json'
    CURVE = SECP256R1

    @classmethod
    def _load_jwk_array(cls, jwks):
        def find(use, op):
            return next(j for j in jwks if j.get('use') == use and op in j.get('key_ops', []))
        pub_sig  = find('sig', 'verify')
        priv_sig = find('sig', 'sign')
        pub_enc  = find('enc', 'decrypt')
        priv_enc = find('enc', 'encrypt')

        x = _bytes_to_int(pub_sig['x'])
        y = _bytes_to_int(pub_sig['y'])
        d = _bytes_to_int(priv_sig['d'])
        pub_nums  = EllipticCurvePublicNumbers(x, y, SECP256R1())
        priv_nums = EllipticCurvePrivateNumbers(d, pub_nums)
        cls.signing_priv = priv_nums.private_key()
        cls.signing_pub  = pub_nums.public_key()

        n  = _bytes_to_int(pub_enc['n'])
        e  = _bytes_to_int(pub_enc['e'])
        d2 = _bytes_to_int(priv_enc['d'])
        p  = _bytes_to_int(priv_enc['p'])
        q  = _bytes_to_int(priv_enc['q'])
        dp = _bytes_to_int(priv_enc['dp'])
        dq = _bytes_to_int(priv_enc['dq'])
        qi = _bytes_to_int(priv_enc['qi'])
        rsa_pub  = RSAPublicNumbers(e, n)
        rsa_priv = RSAPrivateNumbers(p, q, d2, dp, dq, qi, rsa_pub)
        cls.encrypting_priv = rsa_priv.private_key()
        cls.encrypting_pub  = rsa_pub.public_key()

    @classmethod
    def _export_jwk_array(cls):
        pub  = cls.signing_priv.public_key().public_numbers()
        priv = cls.signing_priv.private_numbers()
        ec_pub = {'kty':'EC','crv':'P-256','use':'sig','key_ops':['verify'],
                  'x':_b64url_encode(_int_to_bytes(pub.x, 32)),
                  'y':_b64url_encode(_int_to_bytes(pub.y, 32))}
        ec_priv = dict(ec_pub, key_ops=['sign'], d=_b64url_encode(_int_to_bytes(priv.private_value, 32)))

        rp = cls.encrypting_priv.private_numbers()
        rsa_pub  = {'kty':'RSA','use':'enc','key_ops':['decrypt'],
                    'n':_b64url_encode(_int_to_bytes(rp.public_numbers.n)),
                    'e':_b64url_encode(_int_to_bytes(rp.public_numbers.e))}
        rsa_priv = dict(rsa_pub, key_ops=['encrypt'],
                    d =_b64url_encode(_int_to_bytes(rp.d)),
                    p =_b64url_encode(_int_to_bytes(rp.p)),
                    q =_b64url_encode(_int_to_bytes(rp.q)),
                    dp=_b64url_encode(_int_to_bytes(rp.dmp1)),
                    dq=_b64url_encode(_int_to_bytes(rp.dmq1)),
                    qi=_b64url_encode(_int_to_bytes(rp.iqmp)))
        return [ec_pub, rsa_pub, ec_priv, rsa_priv]

    @classmethod
    def init(cls, key_file=None):
        path = key_file or cls.FILE
        if os.path.exists(path):
            with open(path) as f:
                cls._load_jwk_array(json.load(f))
        else:
            cls.generate(path)

    @classmethod
    def generate(cls, path=None):
        path = path or cls.FILE
        cls.signing_priv    = ec.generate_private_key(SECP256R1())
        cls.signing_pub     = cls.signing_priv.public_key()
        cls.encrypting_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.encrypting_pub  = cls.encrypting_priv.public_key()
        with open(path, 'w') as f:
            json.dump(cls._export_jwk_array(), f)

    @classmethod
    def sign(cls, message):
        raw = cls.signing_priv.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
        # raw is DER; extract r and s for JSON format
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(raw)
        return json.dumps({'r': _b64url_encode(_int_to_bytes(r, 32)),
                           's': _b64url_encode(_int_to_bytes(s, 32))})

    @classmethod
    def verify(cls, message, signature_json):
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        sig = json.loads(signature_json)
        r = _bytes_to_int(sig['r'])
        s = _bytes_to_int(sig['s'])
        der = encode_dss_signature(r, s)
        try:
            cls.signing_pub.verify(der, message.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    @classmethod
    def encrypt(cls, message):
        ct = cls.encrypting_pub.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(ct).decode()

    @classmethod
    def decrypt(cls, ciphertext_b64):
        ct = base64.b64decode(ciphertext_b64)
        return cls.encrypting_priv.decrypt(
            ct,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)).decode()
