#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import os, codecs, json

class RSAC:
  def __init__(self,privatekey=None,publickey=None):
    if type(privatekey)==RSA._RSAobj:
      self.privatekey = privatekey
    elif type(privatekey)==bytes:
      self.privatekey = RSA.importKey(privatekey)
    elif type(privatekey)==str:
      if privatekey.endswith(".pem"):
        self.privatekey = self.__loadKey(privatekey)
      else:
        self.privatekey = RSA.importKey(privatekey)
    else:
      self.privatekey = None
    if type(publickey)==RSA._RSAobj:
      self.publickey = publickey
    elif type(publickey)==bytes:
      self.publickey = RSA.importKey(publickey)
    elif type(publickey)==str:
      if publickey.endswith(".pem"):
        self.publickey = self.__loadKey(publickey)
      else:
        self.publickey = RSA.importKey(publickey)
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
  def sign(self,data):
    """
    returns a hex string for storage purposes and post-verification
    """
    if type(data)==str:
      data = data.encode()
    elif type(data)==dict:
      data = json.dumps(data,sort_keys=True).encode()
    if type(data)==bytes:
      signer = PKCS1_v1_5.new(self.privatekey)
      digest = SHA256.new(data)
      return codecs.encode(signer.sign(digest),"hex_codec").decode()
    return False
  def verify(self,data,signature):
    signature = codecs.decode(signature,"hex_codec")
    if type(data)==str:
      data = data.encode()
    elif type(data)==dict:
      data = json.dumps(data,sort_keys=True).encode()
    if type(data)==bytes:
      signer = PKCS1_v1_5.new(self.publickey)
      digest = SHA256.new(data)
      return signer.verify(digest,signature)
          