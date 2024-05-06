# -*- coding: utf-8 -*-

import base64
import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from sup import get_random_string


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
        mod_iv = hashlib.sha256(self.iv + hashlib.sha256(self.key).digest()).digest()[:16]
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(mod_iv))

    def is_started(self) -> bool:
        return self.cipher is not None

    def encrypt(self, bs: bytes) -> bytes or None:
        if self.is_started():
            bs = inject_salt(bs)
            padder = padding.PKCS7(algorithms.AES256.block_size).padder()
            bs = padder.update(bs) + padder.finalize()

            encryptor = self.cipher.encryptor()
            ct = encryptor.update(bs) + encryptor.finalize()
            return ct
        else:
            return None

    def decrypt(self, ct: bytes) -> bytes or None:
        if self.is_started():
            decryptor = self.cipher.decryptor()
            bs = decryptor.update(ct) + decryptor.finalize()

            unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
            bs = unpadder.update(bs) + unpadder.finalize()
            bs = takeout_salt(bs)
            return bs
        else:
            return None


# https://github.com/pyca/cryptography/issues/3446
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher
# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet


class PycaFernet:
    """
    # First, init:
    ``` python
    cipher = PycaFernet()
    ```

    # Second set password and iv:
    ``` python
    cipher.set_passwort("Your strong🤡 utf-8 password")
    cipher.set_iv(os.urandom(16))  # =)
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
        # key_len = len(Fernet.generate_key())
        pwd = password.encode("utf-8")
        salt = hashlib.sha256(pwd).digest()[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # key_len
            salt=salt,
            iterations=480000
        )
        # self.key = base64.urlsafe_b64encode(kdf.derive(pwd))
        self.key = kdf.derive(pwd)
        self.key = base64.urlsafe_b64encode(self.key)

    def set_iv(self, iv):
        pass  # =)

    def start(self):
        self.cipher = Fernet(self.key)

    def is_started(self) -> bool:
        return self.cipher is not None

    def encrypt(self, bs: bytes) -> bytes or None:
        if self.is_started():
            return self.cipher.encrypt(bs)
        else:
            return None

    def decrypt(self, ct: bytes) -> bytes or None:
        if self.is_started():
            return self.cipher.decrypt(ct)
        else:
            return None


# https://stackoverflow.com/questions/66476150/fast-concatenation-of-bytes-in-python3
def inject_salt(data: bytes) -> bytes:
    salt_prop = 4
    if len(data) == 0:
        # print(0, 1, 1)
        return os.urandom(1)
    salt_slots = 1 + len(data) // salt_prop
    salts = os.urandom(salt_slots)
    len_res = len(data) + salt_slots
    # print(len(data), salt_slots, len_res)
    res = bytearray(len_res)
    i, j, k = 0, 0, 0
    while j < len(res):
        if i % salt_prop == 0:
            res[j] = salts[k]
            j += 1
            k += 1
            if j >= len(res):
                break
        res[j] = data[i]
        i += 1
        j += 1
    return bytes(res)


def takeout_salt(data: bytes) -> bytes:
    salt_prop = 4
    # data_slots = ((len(data)-1)*salt_prop)//(salt_prop+1)
    data_slots = (len(data)-1) % (salt_prop+1)
    data_slots = ((len(data)-1-data_slots)//(salt_prop+1))*salt_prop + data_slots
    # salt_slots = 1 + data_slots // salt_prop
    # print(data_slots, salt_slots, len(data))
    res = bytearray(data_slots)
    i, j, c = 0, 1, 1
    while i < len(res):
        res[i] = data[j]
        if c >= salt_prop:
            j += 1
            c = 0
        c += 1
        i += 1
        j += 1
    return bytes(res)


def transfer_shared_key(shared_key: bytes) -> str:
    return hashlib.sha256(shared_key).hexdigest()


def __test_salt():
    import random
    from alive_progress import alive_bar
    # v, k = 10**9, 256
    # v, k = 10**9, 10**3
    v, k = 10**9, 250000
    # v, k = 10**9, 10**6
    n = v//k
    with alive_bar(n) as bar:
        for i in range(n):
            data_i = os.urandom(random.randint(k-100, k+100))
            salted_i = inject_salt(data_i)
            unsalted_i = takeout_salt(salted_i)
            assert data_i == unsalted_i
            bar()


def __test_cipher():
    import random
    from alive_progress import alive_bar
    cipher = PycaAES256CBC()
    # cipher = PycaFernet()
    cipher.set_iv(os.urandom(16)), cipher.set_password(get_random_string())
    cipher.start()
    v, k = 10 ** 9, 250000
    n = v//k
    with alive_bar(n) as bar:
        for i in range(n):
            data_i = os.urandom(random.randint(k - 100, k + 100))
            data_en = cipher.encrypt(data_i)
            data_de = cipher.decrypt(data_en)
            assert data_i == data_de
            bar()


def __test_key_exchange():
    from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
    from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key1 = X448PrivateKey.generate()
    public_key1 = private_key1.public_key()
    public_key1_bytes = public_key1.public_bytes(encoding=serialization.Encoding.Raw,
                                                 format=serialization.PublicFormat.Raw)
    print(f"Pub key 1 bytes: {public_key1_bytes}")
    public_key1_text = base64.b64encode(public_key1_bytes).decode("ascii")
    print(f"Pub key 1: {public_key1_text}")

    private_key2 = X448PrivateKey.generate()
    public_key2 = private_key2.public_key()
    public_key2_bytes = public_key2.public_bytes(encoding=serialization.Encoding.Raw,
                                                 format=serialization.PublicFormat.Raw)

    print(f"Pub key 2 bytes: {public_key2_bytes}")
    public_key2_text = base64.b64encode(public_key2_bytes).decode("ascii")
    print(f"Pub key 2: {public_key2_text}")

    # =============================

    pubkey1_bytes = base64.b64decode(public_key1_text.encode("ascii"))
    pubkey1 = X448PublicKey.from_public_bytes(pubkey1_bytes)

    pubkey2_bytes = base64.b64decode(public_key2_text.encode("ascii"))
    pubkey2 = X448PublicKey.from_public_bytes(pubkey2_bytes)

    shared_key1 = private_key2.exchange(pubkey1)
    shared_key1 = base64.b64encode(shared_key1).decode("ascii")
    print(f"shared_key1: {shared_key1}")

    shared_key2 = private_key1.exchange(pubkey2)
    shared_key2 = base64.b64encode(shared_key2).decode("ascii")
    print(f"shared_key2: {shared_key2}")


if __name__ == "__main__":
    # __test_salt()
    # __test_cipher()
    __test_key_exchange()
