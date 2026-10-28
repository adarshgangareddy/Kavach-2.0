"""Weak cryptography: labelled cases. Never run."""
import hashlib
import random
import ssl

import requests
from Crypto.Cipher import AES, ARC4, DES
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def should_be_reported(data, password, key, iv, url, ctx):
    a = hashlib.md5(data).hexdigest()  # expect CWE-327
    b = hashlib.sha1(data).hexdigest()  # expect CWE-327
    c = hashlib.new("md5", data)  # expect CWE-327
    d = hashlib.sha256(password.encode()).hexdigest()  # expect CWE-916
    e = DES.new(key, DES.MODE_CBC)  # expect CWE-327
    f = ARC4.new(key)  # expect CWE-327
    g = AES.new(key, AES.MODE_ECB)  # expect CWE-327
    h = Cipher(algorithms.AES(key), modes.ECB())  # expect CWE-327
    i = Cipher(algorithms.TripleDES(key), modes.CBC(iv))  # expect CWE-327
    j = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # expect CWE-326
    k = RSA.generate(1024)  # expect CWE-326
    resp = requests.get(url, verify=False, timeout=5)  # expect CWE-295
    unverified = ssl._create_unverified_context()  # expect CWE-295
    ctx.check_hostname = False  # expect CWE-295
    ctx.verify_mode = ssl.CERT_NONE  # expect CWE-295
    old = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # expect CWE-327
    return a, b, c, d, e, f, g, h, i, j, k, resp, unverified, old


def make_reset_token():
    token = "".join(random.choice("abcdef0123456789") for _ in range(32))  # expect CWE-330
    otp = random.randint(100000, 999999)  # expect CWE-330
    return token, otp


def should_not_be_reported(data, key, url, players):
    etag = hashlib.md5(data, usedforsecurity=False).hexdigest()  # decoy
    digest = hashlib.sha256(data).hexdigest()  # decoy
    blake = hashlib.blake2b(data).hexdigest()  # decoy
    gcm = AES.new(key, AES.MODE_GCM)  # decoy
    strong = rsa.generate_private_key(public_exponent=65537, key_size=3072)  # decoy
    resp = requests.get(url, timeout=5)  # decoy
    ctx = ssl.create_default_context()  # decoy
    dice = random.randint(1, 6)  # decoy
    winner = random.choice(players)  # decoy
    return etag, digest, blake, gcm, strong, resp, ctx, dice, winner
