#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov 14 15:49:52 2017

@author: root
"""

import socket,json,codecs
from RSA import *
from AES import *
"""
info = ("192.168.1.49",5000)
s = socket.socket()
s.connect(info)
#revice pubkey
print("listening for public key...")
pubk = s.recv(4096)
rsa = RSAC(publickey=pubk)
# generate and send crypted AES key
aes = AESC()
enk = rsa.encrypt(aes.key)
print("Sent key: {}\nReal Key: {}".format(enk,aes.key))
s.send(enk)

st = "Hola Ramon Aixo es una prova".encode()
enc = aes.encrypt(st)
print("sending:",enc)
s.send(enc)
print("sent")
s.close()
"""

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
    self.secureConn()
  def htos(self,h):
    return codecs.encode(h,"hex_codec").decode()
  def stoh(self,s):
    return codecs.decode(s,"hex_codec")
      
  def secureConn(self):
    #recive pubk
    print("Connection established.\nWaiting public key")
    pubk = self.frecive()
    print("Public key recived validating...")
    try:
      self.rsa1 = RSAC(publickey=pubk)
      print("Generating AES key...")
      self.aes1 = AESC()
    except Exception as e:
      print("Error with the encription algorithm!",str(e))
      return False
    eskey = self.htos(self.rsa1.encrypt(self.aes1.key))
    print("Generating RSA keys...")
    self.rsa2 = RSAC()
    self.rsa2.generateKeys()
    spkey = self.rsa2.publickey.exportKey("PEM").decode()
    data = {"eaeskey":eskey,"publicKey":spkey}
    print("Sending encrypted AES key and public RSA key...")
    self.fsend(data)
    #waiting for aes encrypted key
    print("Waiting RSA encrypted AES key...")
    aesk = self.stoh(self.frecive())
    print("Decrypting AES key...")
    daesk = self.rsa2.decrypt(aesk)
    self.aes2 = AESC(key=daesk)
    print("Connection secured")
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
    
c = Client(("localhost",4777))
c.sconnect()