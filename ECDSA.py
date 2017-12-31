#!/usr/bin/env python3

# -*- coding: utf-8 -*-

from ecdsa import SigningKey, VerifyingKey, SECP256k1
import hashlib, json

class ECDSA:
  def __init__(self,privatekey=None,publickey=None):
    if (privatekey==None and publickey==None):
      self.generateKeys()
    else:
      self.privatekey = SigningKey.from_string(privatekey,curve=SECP256k1) if privatekey!=None else None
      self.publickey = VerifyingKey.from_string(publickey,curve=SECP256k1) if publickey!=None else None
  def generateKeys(self):
    self.privatekey = SigningKey.generate(curve=SECP256k1)
    self.publickey = self.privatekey.get_verifying_key()
  def sign(self,msg):
    if type(msg)==str:
      msg = msg.encode()
    elif type(msg)==dict:
      msg = json.dumps(msg,sort_keys=True).encode()
    h = hashlib.sha256(msg).digest()
    return self.privatekey.sign(h)
  def verify(self,signature,msg):
    if type(msg)==dict:
      msg = json.dumps(msg,sort_keys=True)
    if type(msg)==str:
      msg = msg.encode()
    h = hashlib.sha256(msg).digest()
    return self.publickey.verify(signature,h)