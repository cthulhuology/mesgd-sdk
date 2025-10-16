import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
import pickle

class PKI:
    FILE = 'pki_keys.bin'
    CURVE = ec.SECP256R1
    RSA_BITS = 2048

    @classmethod
    def init(cls):
        if os.path.exists(cls.FILE):
            with open(cls.FILE, 'rb') as f:
                keys = pickle.load(f)
            cls.signing_priv = serialization.load_pem_private_key(keys['signing_priv'], password=None)
            cls.signing_pub = serialization.load_pem_public_key(keys['signing_pub'])
            cls.encrypting_priv = serialization.load_pem_private_key(keys['encrypting_priv'], password=None)
            cls.encrypting_pub = serialization.load_pem_public_key(keys['encrypting_pub'])
        else:
            signing_priv = ec.generate_private_key(curve=cls.CURVE)
            signing_pub = signing_priv.public_key()
            encrypting_priv = rsa.generate_private_key(public_exponent=65537, key_size=cls.RSA_BITS)
            encrypting_pub = encrypting_priv.public_key()

            signing_priv_pem = signing_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            signing_pub_pem = signing_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            encrypting_priv_pem = encrypting_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            encrypting_pub_pem = encrypting_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            keys = {
                'signing_priv': signing_priv_pem,
                'signing_pub': signing_pub_pem,
                'encrypting_priv': encrypting_priv_pem,
                'encrypting_pub': encrypting_pub_pem
            }
            with open(cls.FILE, 'wb') as f:
                pickle.dump(keys, f)
            cls.signing_priv = serialization.load_pem_private_key(signing_priv_pem, password=None)
            cls.signing_pub = serialization.load_pem_public_key(signing_pub_pem)
            cls.encrypting_priv = serialization.load_pem_private_key(encrypting_priv_pem, password=None)
            cls.encrypting_pub = serialization.load_pem_public_key(encrypting_pub_pem)

    @classmethod
    def sign(cls, message):
        if not hasattr(cls, 'signing_priv'):
            raise ValueError('Keys not initialized')
        signature = cls.signing_priv.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return base64.b64encode(signature).decode()

    @classmethod
    def verify(cls, message, signature_b64):
        if not hasattr(cls, 'signing_pub'):
            raise ValueError('Keys not initialized')
        signature = base64.b64decode(signature_b64)
        try:
            cls.signing_pub.verify(
                signature,
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False

    @classmethod
    def encrypt(cls, message):
        if not hasattr(cls, 'encrypting_pub'):
            raise ValueError('Keys not initialized')
        ciphertext = cls.encrypting_pub.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()

    @classmethod
    def decrypt(cls, ciphertext_b64):
        if not hasattr(cls, 'encrypting_priv'):
            raise ValueError('Keys not initialized')
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = cls.encrypting_priv.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
