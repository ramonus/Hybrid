#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov 14 15:49:52 2017

@author: root
"""

import socket
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
  
  def __init__(self,conf):
    super().__init__()
    self.conf = conf
    self.connect(self.conf)
    #recive pubk
    print("Connection established.\nWaiting public key")
    pubk = self.recv(4096)
    print("Public key recived validating...")


