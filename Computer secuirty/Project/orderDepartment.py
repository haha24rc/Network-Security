import socket  # Import socket module
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA3_256
import threading
import queue
import datetime
from tools import *


def recv_thread(key, s, q): #receives approved purchase orders
    size = s.recv(128, socket.MSG_WAITALL)  # receive size bytes
    if size:
        size = int.from_bytes(size, 'big')
        msg = b''
        i = size
        while i > 0:  # empty socket buffer into msg (based on the size byte)
            if (i < 1024):
                msg += s.recv(i, socket.MSG_WAITALL)
                i -= size
            else:
                msg += s.recv(1024, socket.MSG_WAITALL)
                i -= 1024

    while (size != b''):
        msg = decrypt(msg, key) #decrypt msg
        msg = remove_space_padding(msg)
        name, cost, amount, sig1, PUP, sig2, PUP2, timestamp = msg.split(b'|,|') #retreive msg elements
        timestamp = (int)(timestamp.decode())
        teststamp = (int)(''.join(datetime.datetime.now().strftime('%S')))
        if ((teststamp - timestamp) < 5):   #check timestamp validity
            hash = SHA3_256.new(name + b'|,|' + cost + b'|,|' + amount)
            PU = RSA.import_key(PUP)
            ver = PKCS1_PSS.new(PU)
            ver.verify(hash, sig1)  #verify client signature
            PU2 = RSA.import_key(PUP2)
            ver2 = PKCS1_PSS.new(PU2)
            ver2.verify(hash, sig2) #verify supervisor signature
            q.put(name + b'|,|' + cost + b'|,|' + amount + b'|,|' + sig1 + b'|,|' + PUP + b'|,|' + sig2 + b'|,|' + PUP2)
        else:
            raise ValueError('Timestamp invalid')

        size = s.recv(128, socket.MSG_WAITALL)  # receive next size bytes
        if size:
            size = int.from_bytes(size, 'big')
            msg = b''
            i = size
            while i > 0:  # empty next msg into msg (based on the size byte)
                if (i < 1024):
                    msg += s.recv(i, socket.MSG_WAITALL)
                    i -= size
                else:
                    msg += s.recv(1024, socket.MSG_WAITALL)
                    i -= 1024


def main():
    s = socket.socket()  # Create a socket object
    port = 60000  # Reserve a port for your service.

    s.connect(('127.0.0.1', port))  # Connect to server

    PRA, PUA, ks = authentificate(s,"orderDepartment")  #authenticate the order department
    q = queue.Queue(maxsize=0)

    t1 = threading.Thread(target=recv_thread, args=(ks, s, q), daemon=True)  # start thread for receiving msgs
    t1.start()

    while (True):
        try: #display approved msgs as they are received and added to the queue, busy wait otherwise 
            if (q.qsize() != 0):
                rmsg = q.get()
                name, cost, amount, sig1, PUP, sig2, PUP2 = rmsg.split(b'|,|')
                print("\nOrder Received")
                print("Name: " + name.decode() + " Unit Cost: " + cost.decode() + " Amount: " + amount.decode())

        except KeyboardInterrupt:
            break

    s.shutdown(socket.SHUT_RDWR) #close socket after finishing
    s.close()


if __name__ == "__main__":
    main()