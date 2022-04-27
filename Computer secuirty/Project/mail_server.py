from asyncio.windows_events import NULL
import socket                   # Import socket module
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from tools import *
import threading
import _thread as thread
import queue

port = 60000                    # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
print(host)
s.bind(('127.0.0.1', port))     # Bind to the port
s.listen(5)                     # Now wait for client connection.

#generate public and private key
rsa = RSA.generate(2048)
server_puKey = rsa.public_key()
server_prKey = PKCS1_OAEP.new(rsa)

#3 conn and 3 session keys
supervisor = NULL
orderDepartment  = NULL
client  = NULL
ks_supervisor = NULL
ks_orderDep = NULL
ks_client = NULL

def addTimestamp(msg): #add timestamp to a msg
    timestamp = ''.join(datetime.datetime.now().strftime('%S'))
    msg = append_space_padding(msg + b'|,|' + timestamp.encode())
    return msg

def authentificate(conn,addr):
    # send and receive public key
    recv_pubKey = conn.recv(1024)
    user_puKey = RSA.importKey(recv_pubKey)
    user_puKey = PKCS1_OAEP.new(user_puKey)
    conn.send(server_puKey.export_key())

    #msg1
    msg1 = conn.recv(256, socket.MSG_WAITALL)
    de_msg1 = server_prKey.decrypt(msg1)
    N1, id = de_msg1.split(b'|,|') 
    
    #msg2
    N2 = nonce()
    msg2 = N1 + b'|,|' + N2
    en_msg2 = user_puKey.encrypt(msg2)
    conn.send(en_msg2)

    #msg3
    msg3 = conn.recv(256, socket.MSG_WAITALL)
    de_msg3 = server_prKey.decrypt(msg3)
    if(de_msg3 != N2):
        print("One invalid connection:",addr)
        conn.close()
    
    #msg4

    msg4 = conn.recv(256, socket.MSG_WAITALL)
    de_msg4 = server_prKey.decrypt(msg4)
    ks, sig = de_msg4.split(b'|,|')

    return id.decode(),ks,sig
        
def sendMsg(msg, n):
    sent = 0
    while(True):
        if(n == 1):                         #send msg to supervisor
            if (supervisor != NULL):
                en_msg = encrypt(msg, ks_supervisor)
                supervisor.send(len(en_msg).to_bytes(128,'big') + en_msg)
                sent += 1
        elif n == 2:
            if (orderDepartment != NULL):   #send msg to orderDepartment
                en_msg = encrypt(msg, ks_orderDep)
                orderDepartment.send(len(en_msg).to_bytes(128,'big') + en_msg)
                sent += 1
        if(sent > 0):
            break

def supervisorThread(q_c):
    print("Supervisor is logged in")
    while(True):
        if(q_c.qsize() != 0):        #client send msg to supervisor
            msg = q_c.get()
            msg = addTimestamp(msg)
            sendMsg(msg,1)

def orderDepartmentThread(q_s):
    print("Order Department is logged in")
    while(True):
        if(q_s.qsize() != 0):        #supervisor msg to orderDepartment
            msg = q_s.get()
            msg = addTimestamp(msg)
            sendMsg(msg,2)

def clientThread():
    print("Client is logged in")
    #Client does not receive msgs


if __name__  == "__main__":            
    q_s = queue.Queue(maxsize=0)
    q_o = queue.Queue(maxsize=0)
    q_c = queue.Queue(maxsize=0)
    while(True):
        try:
            conn, addr = s.accept()     # Establish connection with client.
            
            id,ks,sig = authentificate(conn,addr) #authenticate conncection and determine id
            #start the required threads to service the connected user
            if(id == "supervisor"):
                supervisor = conn
                ks_supervisor = ks
                t1 = threading.Thread(target=recv_thread,args=(ks_supervisor,supervisor,q_s),daemon=True)
                t1.start()
                thread.start_new_thread(supervisorThread ,(q_c,))
            elif(id == "orderDepartment"):
                orderDepartment = conn
                ks_orderDep = ks
                thread.start_new_thread(orderDepartmentThread,(q_s,))
            elif(id == "client"):
                client = conn
                ks_client = ks
                t3 = threading.Thread(target=recv_thread,args=(ks_client,client,q_c),daemon=True)
                t3.start()
                thread.start_new_thread(clientThread, ())
        except KeyboardInterrupt:
            break
    #close open connections
    supervisor.shutdown(socket.SHUT_RDWR)
    supervisor.close()

    client.shutdown(socket.SHUT_RDWR)
    client.close()

    orderDepartment.shutdown(socket.SHUT_RDWR)
    orderDepartment.close()
