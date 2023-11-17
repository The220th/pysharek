# -*- coding: utf-8 -*-

import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# https://github.com/pyca/cryptography/issues/3446
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher
# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
class PycaAES256CBC:

    def __init__(self, password: str, iv: bytes):
        pwd = password.encode("utf-8")
        salt = hashlib.sha256(pwd).digest()[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000
        )
        key = base64.urlsafe_b64encode(kdf.derive(pwd))
        self.iv = iv
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv))


    def encrypt(self, bs: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        ct = encryptor.update(bs) + encryptor.finalize()
        return ct


    def decrypt(self, ct: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        bs = decryptor.update(ct) + decryptor.finalize()
        return bs
