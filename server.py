#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import socket,threading,json,codecs
from AES import *
from RSA import *

class Server(socket.socket):
  
  def __init__(self,conf=('',4777)):
    super().__init__(socket.AF_INET,socket.SOCK_STREAM)
    self.ip,self.port = self.conf = conf
    self.running = False
    self.connections = []
    self.cThreads = []
  def start(self):
    #listen for connections
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.bind(self.conf)
    self.listen(1)
    self.running = True
    while self.running:
      print("Waiting connections...")
      conn,addr = cinfo = self.accept()
      print("Connection established with:",addr[0])
      self.connections.append(cinfo)
      th = threading.Thread(target=self.__cHandler,args=cinfo)
      th.start()
      self.cThreads.append(th)
      
  def stop(self):
    self.close()
  def htos(self,h):
    return codecs.encode(h,"hex_codec").decode()
  def stoh(self,s):
    return codecs.decode(s,"hex_codec")
  
  def __cHandler(self,conn,addr):
    print("Handling connection from:",addr[0])
    #start secure connection
    self.scon = SecureConnection(conn)
    self.scon.secure()
    
  def fsend(self,conn,data):
    try:
      data = json.dumps(data)
    except:
      pass
    data = data.encode()
    conn.send(data)
  def frecive(self,conn):
    data = conn.recv(4096)
    try:
      data = json.loads(data)
    except:
      pass
    print("Recived type:",type(data))
    return data
  
class SecureConnection:
  def __init__(self,conn):
    self.conn = conn
  def secure(self):
    #generate AES and RSA keys
    self.rsa_recive = RSAC()
    self.rsa_recive.generateKeys()
    self.aes_send = AESC()
    #send rsa public key
    self.__sendPubk()
    #recive encrypted AES key and public key from client
    self.__reciveKeys()
    self.__sendEkey()
    self.__sendVerification()
    self.__waitMessages()
  def __waitMessages(self):
    d = ""
    while d!="EXIT":
      d = self.conn.recv(4096)
      d = self.aes_recive.decrypt(d)
      print(d)
  def __sendVerification(self,msg="Test message"):
    self.conn.send(self.aes_send.encrypt(msg.encode()))
  def __sendPubk(self):
    pubk = self.rsa_recive.publickey.exportKey("PEM")
    if type(pubk)==bytes:
      self.conn.send(pubk)
  def __reciveKeys(self):
    data = self.conn.recv(4096).decode()
    data = json.loads(data)
    # configure objs
    self.rsa_key = RSAC(publickey=bytes(data["pubk"]))
    aes_send_key = self.rsa_recive.decrypt(bytes(data["aeskey"]))
    self.aes_recive = AESC(key=aes_send_key)
  def __sendEkey(self):
    ekey = self.rsa_key.encrypt(self.aes_send.key)
    self.conn.send(ekey)
s = Server()
s.start()
