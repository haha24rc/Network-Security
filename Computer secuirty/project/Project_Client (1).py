from asyncio.windows_events import NULL
import socket                   # Import socket module
from Crypto.Cipher import DES,PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import PKCS1_PSS
import random
from Crypto.Hash import SHA3_256
from tools import *
from sys import getsizeof
import threading
import _thread as thread
import queue
import datetime


def main():
    s = socket.socket()             # Create a socket object
    port = 60000                    # Reserve a port for your service.

    s.connect(('127.0.0.1', port))  # Connect to server

    itemName = input("Please state the name of the item")
    itemName = itemName # converting from str to bytes

    unitCost = input("What is the unit cost of one item? (do not add the $ sign)")
    unitCost = unitCost# converting from str to bytes

    amount = input("Please enter the amount that you're ordering")

    PRA, PUA, ks = authentificate(s, "client")
    q = queue.Queue(maxsize=0)

    hash = SHA3_256.new(itemName.encode() + b',' + unitCost.encode() + b',' + amount.encode())
    signer = PKCS1_PSS.new(PRA)
    sig = signer.sign(hash)
    timestamp = ''.join(datetime.datetime.now().strftime('%S'))

    t1 = threading.Thread(target=recv_thread,args=(ks,s,q),daemon=True) #start thread for receiving msgs
    t1.start()

    userinput = "" #stores clients input
    msg = append_space_padding(itemName.encode() + b',' + unitCost.encode() + b',' + amount.encode() + b',' + sig + b',' + PUA.export_key() + b',' + timestamp.encode()) #encrypts msg and the msg id
    msg = encrypt(msg,ks)
    s.sendall(len(msg).to_bytes(128,'big') + msg)

    while True:
         if (q.qsize() != 0):
             continue

    s.shutdown(socket.SHUT_RDWR)
    s.close()

if __name__ == "__main__":
	main()