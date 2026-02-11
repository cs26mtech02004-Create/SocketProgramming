import hashlib
import hmac
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_encrypt(message, dh_secretkey):
    key = hashlib.sha256(str(dh_secretkey).encode()).digest()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    cipher_data = aesgcm.encrypt(nonce, message, b"")
    return nonce + cipher_data

def aes_decrypt(encrypted_data, dh_secretkey):
    key = hashlib.sha256(str(dh_secretkey).encode()).digest()
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    cipher_text = encrypted_data[12:]
    plaintext_bytes = aesgcm.decrypt(nonce, cipher_text, b"")
    return plaintext_bytes

def verify_mac(data, seq_no, dh_secretkey, received_mac):
    key = hashlib.sha256(str(dh_secretkey).encode()).digest()
    msg = seq_no.to_bytes(4, "big") + data
    expected_mac = hmac.new(key, msg, hashlib.sha256).digest()
    return hmac.compare_digest(expected_mac, received_mac)


def compute_mac(plain_data, seq_no, dh_secretkey):
    key = hashlib.sha256(str(dh_secretkey).encode()).digest()
    msg = seq_no.to_bytes(4, "big") + plain_data
    return hmac.new(key, msg, hashlib.sha256).digest()        #ye hmac hamesha 32 byte generate karega


# ---- Test k liye data h----
# edata = aes_encrypt(b"hello world!", b"0102030405060708")
# print(edata)
#
# print(aes_decrypt(edata, b"0102030405060708"))
