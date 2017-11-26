#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov 14 15:49:52 2017

@author: root
"""

import socket,json,codecs
from RSA import *
from AES import *

class Client(socket.socket):
  
  def __init__(self,conf=None):
    super().__init__()
    self.conf = conf
  def sconnect(self,conf=None):
    if conf!=None:
      self.conf = conf
    print("Connecting to:",self.conf)
    self.connect(self.conf)
    #start secure connection
    self.scon = SecureConnection(self)
    self.scon.secure()
  def htos(self,h):
    return codecs.encode(h,"hex_codec").decode()
  def stoh(self,s):
    return codecs.decode(s,"hex_codec")
  def fsend(self,data):
    try:
      data = json.dumps(data)
    except:
      pass
    data = data.encode()
    self.send(data)
  def frecive(self):
    data = self.recv(4096)
    try:
      data = json.loads(data)
    except:
      pass
    return data
class SecureConnection:
  def __init__(self,conn):
    self.conn = conn
  def secure(self):
    #generate RSA and AES key
    self.rsa_recive = RSAC()
    self.rsa_recive.generateKeys()
    self.aes_send = AESC()
    #wait for pubk
    self.__recivePubk()
    self.__sendAPK()
    self.__reciveEkey()
    aesk1 = self.aes_send.key
    aesk2 = self.aes_recive.key
    print(aesk1,aesk2,sep="\n")
    
  def __reciveEkey(self):
    ekey = self.conn.recv(4096)
    key = self.rsa_recive.decrypt(ekey)
    self.aes_recive = AESC(key=key)
  def __sendAPK(self):
    eakey = self.rsa_send.encrypt(self.aes_send.key)
    pkey = self.rsa_recive.publickey.exportKey("PEM")
    data = {"pubk":list(pkey),"aeskey":list(eakey)}
    self.conn.send(json.dumps(data).encode())
  def __recivePubk(self):
    data = self.conn.recv(4096)
    self.rsa_send = RSAC(publickey=data)
    
    
c = Client(("localhost",4777))
c.sconnect()