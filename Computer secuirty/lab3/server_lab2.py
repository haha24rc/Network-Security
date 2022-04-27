import socket                   # Import socket module
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import random
from Crypto.Hash import SHA512
from sys import getsizeof

port = 60000                    # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
print(host)
s.bind(('127.0.0.1', port))            # Bind to the port
s.listen(5)                     # Now wait for client connection.

IDb = 'RESPONDER B'

def append_space_padding(plaintext, blocksize=8):
    n = len(plaintext) % blocksize
    return plaintext + ('\n' * (blocksize - n))

def remove_space_padding(str, blocksize=8):
    return str.replace('\n','')

def encrypt(Plaintext_pad, key):
    iv = Random.new().read(DES.block_size)
    cipher = DES.new(key,DES.MODE_OFB,iv)
    en_text = cipher.encrypt(Plaintext_pad.encode())
    return iv + en_text

def decrypt(ciphertext, key):
    iv = ciphertext[:8]
    text = ciphertext[8:]
    cipher = DES.new(key, DES.MODE_OFB, iv)
    de_text = cipher.decrypt(text)
    return de_text.decode()

def nonce():
    return ''.join((str)(random.randrange(0,2)) for i in range(8))

#generate public and private key
rsa = RSA.generate(2048, Random.new().read)
privateKey = rsa.exportKey()
publicKey = rsa.publickey().exportKey()
prKeyB = RSA.importKey(privateKey)
prKeyB = PKCS1_OAEP.new(prKeyB)

N2 = nonce()

while True:
    conn, addr = s.accept()     # Establish connection with client.

    # send and receive public key
    conn.send(publicKey)
    recv_pubKey = conn.recv(2048)
    puKeyA = RSA.importKey(recv_pubKey)
    puKeyA = PKCS1_OAEP.new(puKeyA)

    #(1)
    msg1 = conn.recv(256)
    de_msg1 = prKeyB.decrypt(msg1).decode()
    N1 = de_msg1[0:8]
    print("The decrypted message 1:",de_msg1,'\n')

    #(2)
    msg2 = N1 + ' || ' + N2
    en_msg2 = puKeyA.encrypt(msg2.encode())
    conn.send(en_msg2)
    print('The message 2: "', msg2, '" is sent\n')

    #(3)
    msg3 = conn.recv(256)
    de_msg3 = prKeyB.decrypt(msg3).decode()
    print("The decrypted message 3:",de_msg3,'\n')

    #(4)
    msg4 = conn.recv(256)
    de_msg4 = prKeyB.decrypt(msg4).decode()
    print("The decrypted message 4:",de_msg4,'\n')


    # send text or image
    # Uncommend line 84 and commend line 85 to receive text file
    
    # file = open('text.txt','rb')
    file = open('image.jpg','rb')
    text = file.read()
    file.close()

    while True:
        if(len(text) >= 256):
            msg5 = text[0:206]
            text = text[206:]
        else:
            msg5 = text
            en_msg5 = puKeyA.encrypt(msg5)
            conn.send(en_msg5)
            break

        en_msg5 = puKeyA.encrypt(msg5)
        conn.send(en_msg5)
    print('Image or text file is sent')
    conn.send('ENDOFFILE'.encode())

    conn.close()
