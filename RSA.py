#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov 14 14:13:00 2017

@author: root
"""

from Crypto.PublicKey import RSA
import os

class RSAC:
    def __init__(self,privatekey=None,publickey=None):
        if type(privatekey)==bytes:
            self.privatekey = RSA.importKey(privatekey)
        elif type(privatekey)==str:
            self.privatekey = self.__loadKey(privatekey)
        else:
            self.privatekey = None
        if type(publickey)==bytes:
            self.publickey = RSA.importKey(publickey)
        elif type(publickey)==str:
            self.publickey = self.__loadKey(publickey)
        else:
            self.publickey = None
    def __createPrivateKey(self,b=2048):
        key = RSA.generate(b)
        return key
    def __loadKey(self,fn):
        with open(fn,"rb") as f:
            key = RSA.importKey(f.read())
        return key
    def __createPublicKey(self,pk):
        return pk.publickey()
    def generateKeys(self,b=2048):
        self.privatekey = self.__createPrivateKey(b)
        self.publickey = self.__createPublicKey(self.privatekey)
    def savePrivateKey(self,fn="keys/private.pem"):
        if not os.path.exists("keys/"):
            os.makedirs("keys")
        with open(fn,"wb") as f:
            f.write(self.privatekey.exportKey("PEM"))
    def savePublicKey(self,fn="keys/public.pem"):
        if not os.path.exists("keys/"):
            os.makedirs("keys")
        with open(fn,"wb") as f:
            f.write(self.publickey.exportKey("PEM"))
    def encrypt(self,plaintext):
        if type(plaintext)==str:
            plaintext = plaintext.encode()
        if type(plaintext)==bytes:
            return self.publickey.encrypt(plaintext,"x")[0]
        return None
    def decrypt(self,encryptedtext):
        if type(encryptedtext)==bytes:
            return self.privatekey.decrypt(encryptedtext)
            