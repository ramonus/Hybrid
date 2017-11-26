#!/usr/bin/python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib, os


class AESC:
  def __init__(self,key=None,BS=32):
    self.BS=BS
    if key == None:
      key = os.urandom(BS)
      self.key = self.hashKey(key)
    elif type(key)==str:
      self.key = key.encode()
    else:
      self.key = key
  def randomKey(self,BS=32):
    return os.urandom(BS)
  def hashKey(self,key):
    return hashlib.sha256(key).digest()
  def pad(self,s):
    return s + (self.BS - len(s)%self.BS)*chr(self.BS - len(s)%self.BS)
  def encrypt(self,plaindata):
    if type(plaindata)==bytes:
      plaindata = plaindata.decode("utf-8")
    raw = self.pad(plaindata)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(self.key, AES.MODE_CBC, iv)
    return base64.b64encode(iv+cipher.encrypt(raw))
  def unpad(self,s):
    return s[:-ord(s[len(s)-1:])]
  def decrypt(self,encodeddata):
    encodeddata = base64.b64decode(encodeddata)
    iv = encodeddata[:AES.block_size]
    cipher = AES.new(self.key,AES.MODE_CBC, iv)
    return self.unpad(cipher.decrypt(encodeddata[AES.block_size:])).decode()
        

