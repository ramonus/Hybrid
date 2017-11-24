# -*- coding: utf-8 -*-
"""
Editor de Spyder

Este es un archivo temporal
"""


import socket,threading,json
from AES import *
from RSA import *

def main():
    #server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    port = 5000
    s.bind(("",port))
    
    s.listen(1)
    print("Listening connections...")
    conn,addr = s.accept()
    print("Connection from:",str(addr))
    # send public key
    rsa = RSAC()
    rsa.generateKeys()
    print("Sending public key")
    conn.send(rsa.publickey.exportKey("PEM"))
    print("public key sent")
    #waiting for his AES key
    ekey = conn.recv(4096)
    key = rsa.decrypt(ekey)
    aes = AESC(key)
    print("Recived key: {}\nDecrypted key: {}".format(ekey,key))
    data = conn.recv(4096)
    print("\nRecived data: {}\nDecrypted data: {}".format(data,aes.decrypt(data)))
    conn.close()
    s.close()
    print("End")
    return rsa,aes,ekey,key
  
class server(socket.socket):
  
  def __init__(self,conf=('',4777)):
    super().__init__(socket.AF_INET,socket.SOCK_STREAM)
    self.ip,self.port = self.conf = conf
    self.running = False
    self.connections = []
  def start(self):
    #listen for connections
    self.bind(self.conf)
    self.listen(1)
    self.running = True
    while self.running:
      conn,addr = cinfo = self.accept()
      self.connections.append(cinfo)
      th = threading.Thread(target=self.__cHandler,args=cinfo)
      th.start()
      self.cThreads.append(th)
      
  def stop(self):
    self.close()
  def __cHandler(self,conn,addr):
    print("Handling connection from:",addr[0])
    #start secure connection
    
  def secureConn(self,conn):
    self.rsa = RSAC()
    self.rsa.generateKeys()
    conn.send(self.rsa.publickey.exportKey("PEM").decode())
    data = json.loads(conn.recv(4096))
    eaeskey = data["eaeskey"]
    