# -*- coding: utf-8 -*-
"""
Editor de Spyder

Este es un archivo temporal
"""


import socket
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
    return rsa,aes,ekey,key,