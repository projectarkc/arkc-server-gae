#!/usr/bin/env python
# coding:utf-8

from Crypto.Cipher import AES


class AESCipher:
    """A reusable wrapper of PyCrypto's AES cipher, i.e. resets every time."""
    """ BY Teba 2015 """

    # in new version, segment size is 128

    def __init__(self, password, iv):
        self.password = password
        self.iv = iv
        try:
            self.cipher = AES.new(
                self.password, AES.MODE_CFB, self.iv, segment_size=AES.block_size * 8)
        except Exception as err:
            print(err)
            print(self.password)
            print(len(self.password))

    def encrypt(self, data):
        raw = data.ljust(16 * (len(data) // 16 + 1), b'\x01')
        # print( len(raw)) # TEBA: Why I never get the output?
        enc = self.cipher.encrypt(raw)
        self.cipher = AES.new(
            self.password, AES.MODE_CFB, self.iv, segment_size=AES.block_size * 8)
        return enc

    def decrypt(self, data):
        dec = self.cipher.decrypt()
        self.cipher = AES.new(
            self.password, AES.MODE_CFB, self.iv, segment_size=AES.block_size * 8)
        return dec.rstrip(b'\x01')
