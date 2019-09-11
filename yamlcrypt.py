#!/usr/bin/env python

from __future__ import print_function
import argparse
import base64
import hashlib
import os
import sys
import yaml
from Crypto import Random
from Crypto.Cipher import AES


crypt_prefix = "CRYPT#"

class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """

    def __init__(self, key):
        self.key = hashlib.md5(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf-8'))
        if isinstance(data, u_type):
            return data.encode('utf-8')
        return data

    def _pad(self, s):
        return s + (AES.block_size - len(s) % AES.block_size) * AESCipher.str_to_bytes(
            chr(AES.block_size - len(s) % AES.block_size))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Utility to encrypt/decrypt YAML values (decrypt by default)")
    parser.add_argument(
        "-encrypt",
        action="store_true",
        help="Encrypt values"
    )
    parser.add_argument(
        "-key",
        help="The key in YAML for encryption (default \"secrets\")",
        metavar="KEY",
        default="secrets"
    )
    parser.add_argument(
        "-password",
        help="Password for encryption. NOT SAFE! It is better to use the environment variable $YAML_PASSWORD",
        metavar="SECRET"
    )
    parser.add_argument("file", metavar="FILE", help="YAML file")
    args = parser.parse_args()

    if args.password:
        password = args.password
    else:
        password = os.getenv('YAML_PASSWORD')
    if not password:
        print("ERROR: Password not specified!", file=sys.stderr)
        exit(1)

    cipher = AESCipher(password)

    with open(args.file, 'r') as stream:
        try:
            yml = yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc, file=sys.stderr)
            exit(2)

    for secret, value in yml['secrets'].items():
        if args.encrypt:
            if not value.startswith(crypt_prefix):
                yml[args.key][secret] = crypt_prefix+cipher.encrypt(value)
        else:
            if value.startswith(crypt_prefix):
                value = value[len(crypt_prefix):]
            yml[args.key][secret] = cipher.decrypt(value)

    print(yaml.safe_dump(yml, allow_unicode=True, default_flow_style=False, explicit_start=True), end='')
