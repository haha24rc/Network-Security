from hashlib import sha256
from Crypto import Random
import socket                   # Import socket module
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA3_256
import threading
import queue
import datetime
from tools import *

def append_space_padding(plaintext, blocksize=8):
    # pad the plaintext at the end so that the length is a multiple of the blocksize
    padded_plaintext = pad(plaintext,blocksize)
    return padded_plaintext
 

def encrypt(Plaintext_pad, key):
    # Encrypt the padded plaintext using single DES
    cipher = DES.new(key,DES.MODE_CBC)
    cipher_text = cipher.encrypt(Plaintext_pad)

    return cipher.iv + cipher_text

def remove_space_padding(str, blocksize=8):
    # Unpad the decrypted bytestream
    unpadded_text = unpad(str,blocksize)
    unpadded_text = unpadded_text[8:]

    return unpadded_text

def decrypt(ciphertext, key):
    # Decrypt the cipher text using single DES
    cipher = DES.new(key,DES.MODE_CBC)
    plain_text = cipher.decrypt(ciphertext)

    return plain_text

def recv_thread(key,s,q):
    size = s.recv(128, socket.MSG_WAITALL)    #receive size bytes
    if size:
        size = int.from_bytes(size,'big')
        msg = b''
        i = size
        while i > 0: #empty socket buffer into msg (based on the size byte)
            if (i < 1024):
                msg += s.recv(i, socket.MSG_WAITALL)
                i-=size
            else:
                msg += s.recv(1024, socket.MSG_WAITALL)
                i-=1024

    while(size != b''):
        #print('\nRecieved ciphertext: ' + msg.hex()) #print revieved ciphertext
        msg = decrypt(msg,key)
        msg = remove_space_padding(msg)
        #print('Decrypted message: ' + msg.decode())
        name, cost, amount, sig1, PUP, timestamp = msg.split(b',')
        timestamp = (int) (timestamp.decode())
        teststamp = (int) (''.join(datetime.datetime.now().strftime('%S')))
        if ((teststamp - timestamp) < 5):
            hash = SHA3_256.new(name + b',' + cost + b',' + amount)
            PU = RSA.import_key(PUP)
            ver = PKCS1_PSS.new(PU)
            ver.verify(hash,sig1) 
            q.put(name + b',' + cost + b',' + amount + b',' + sig1 + b',' + PUP)
        else:
            raise ValueError('Timestamp invalid')

        size = s.recv(128, socket.MSG_WAITALL)    #receive next size bytes
        if size:
            size = int.from_bytes(size,'big')
            msg = b''
            i = size
            while i > 0: #empty next msg into msg (based on the size byte)
                if (i < 1024):
                    msg += s.recv(i, socket.MSG_WAITALL)
                    i-=size
                else:
                    msg += s.recv(1024, socket.MSG_WAITALL)
                    i-=1024
    
def main():
    s = socket.socket()             # Create a socket object
    port = 60000                    # Reserve a port for your service.

    s.connect(('127.0.0.1', port))  # Connect to server

    PRA, PUA, ks = authentificate(s, "supervisor")
    q = queue.Queue(maxsize=0)
    
    t1 = threading.Thread(target=recv_thread,args=(ks,s,q),daemon=True) #start thread for receiving msgs
    t1.start()

    userinput = "" #stores clients input
    while(True):
        try:
            if (q.qsize() != 0):
                rmsg = q.get()
                name, cost, amount, sig1, PUP = rmsg.split(b',')
                print("\nOrder Received, do you approve?")
                print("Name: " + name.decode() + " Unit Cost: " + cost.decode() + " Amount: " + amount.decode())
                
                while (userinput.lower() != "yes" and userinput.lower() != "no"):
                    print("Please enter yes or no")
                    userinput = input()
                
                if (userinput.lower() == "yes"):
                    hash = SHA3_256.new(name + b',' + cost + b',' + amount)
                    signer = PKCS1_PSS.new(PRA)
                    sig2 = signer.sign(hash)
                    timestamp = ''.join(datetime.datetime.now().strftime('%S'))
                    msg = append_space_padding(rmsg + b',' + sig2 + b',' + PUA.export_key() + b',' + timestamp.encode()) #encrypts msg and the msg id
                    msg = encrypt(msg,ks)
                    s.sendall(len(msg).to_bytes(128,'big') + msg) #sends size along with encrypted msg

        except KeyboardInterrupt:
            break

    s.shutdown(socket.SHUT_RDWR)
    s.close()

if __name__ == "__main__":
	main()