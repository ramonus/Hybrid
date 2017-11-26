# -*- coding: utf-8 -*-
"""
Editor de Spyder

Este es un archivo temporal
"""


import socket,threading,json,codecs
from AES import *
from RSA import *

"""
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
"""
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
"""
  def secureConn(self,conn):
    print("Generating RSA keys...")
    self.rsa = RSAC()
    self.rsa.generateKeys()
    spkey = self.rsa.publickey.exportKey("PEM").decode()
    print("Sending RSA public key...")
    self.fsend(conn,spkey)
    print("Reciving RSA public key and RSA encrypted AES key...")
    data = self.frecive(conn)
    erkey = self.stoh(data["eaeskey"])
    cpubk = data["publicKey"]
    #decrypt aes 
    print("Decrypting AES key...")
    key = self.rsa.decrypt(erkey)
    self.aesrecive = AESC(key=key)
    # encrypt aes with publickey recived
    self.rsa2 = RSAC(publickey=cpubk)
    print("Generating AES key...")
    self.aessend = AESC()
    print("Encrypting AES key...")
    eskey = self.htos(self.rsa2.encrypt(self.aessend.key))
    print("Sending AES key...")
    self.fsend(conn,eskey)
    print("Connection secured")
"""
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
    aesk1 = self.aes_send.key
    aesk2 = self.aes_recive.key
    print(aesk1,aesk2,sep="\n")
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
