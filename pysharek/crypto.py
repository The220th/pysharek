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
    """
    # First, init:
    ``` python
    cipher = PycaAES256CBC()
    ```

    # Second set password and iv:
    ``` python
    cipher.set_passwort("Your strong🤡 utf-8 password")
    cipher.set_iv(os.urandom(16))
    ```

    # Third start cipher:
    ``` python
    cipher.start()
    ```

    # Fourth use:

    ``` python
    text = "Secret message"
    encrypted_message = cipher.encrypt(text.encode("utf-8"))
    decrypted_message = cipher.decrypt(encrypted_message)
    assert decrypted_message.decode("utf-8") == text
    ```
    """

    def __init__(self):
        self.iv = None
        self.key = None
        self.cipher = None

    def set_password(self, password: str):
        pwd = password.encode("utf-8")
        salt = hashlib.sha256(pwd).digest()[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000
        )
        # self.key = base64.urlsafe_b64encode(kdf.derive(pwd))
        self.key = kdf.derive(pwd)

    def set_iv(self, iv: bytes):
        self.iv = iv

    def start(self):
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))

    def is_started(self) -> bool:
        return self.cipher is not None

    def encrypt(self, bs: bytes) -> bytes or None:
        if self.is_started():
            encryptor = self.cipher.encryptor()
            ct = encryptor.update(bs) + encryptor.finalize()
            return ct
        else:
            return None

    def decrypt(self, ct: bytes) -> bytes or None:
        if self.is_started():
            decryptor = self.cipher.decryptor()
            bs = decryptor.update(ct) + decryptor.finalize()
            return bs
        else:
            return None
