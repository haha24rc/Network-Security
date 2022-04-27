from asyncio.windows_events import NULL
import socket                   # Import socket module
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto import Random
import random
from PIL import Image
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
from sys import getsizeof
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
    d_cipher = DES.new(key, DES.MODE_OFB, iv)
    de_text = d_cipher.decrypt(text)
    return de_text.decode()

def nonce():
    return ''.join((str)(random.randrange(0,2)) for i in range(8))

s = socket.socket()             # Create a socket object
port = 60000                    # Reserve a port for your service.
IDa = 'INITIATOR A'
Ks = 'RYERSON'

s.connect(('127.0.0.1', port))
print('Connected to the host\n\n')

#generate public and private key
rsa = RSA.generate(2048, Random.new().read)
privateKey = rsa.exportKey()
publicKey = rsa.publickey().exportKey()
prKeyA = RSA.importKey(privateKey)
prKeyA = PKCS1_OAEP.new(prKeyA)

N1 = nonce()
      
#Send the public key to the server and receive public key from the server
recv_puKey = s.recv(2048)
puKeyB = RSA.importKey(recv_puKey)
s.send(publicKey)

#(1)
msg1 = N1 + ' || ' + IDa
puKeyB = PKCS1_OAEP.new(puKeyB)
en_msg1 = puKeyB.encrypt(msg1.encode())
s.send(en_msg1)
print('The message 1: "', msg1, '" is sent\n')

#(2)
msg2 = s.recv(256)
de_msg2 = prKeyA.decrypt(msg2).decode()
N2 = de_msg2[12:]
print("The decrypted message 2:",de_msg2,'\n')

#(3)
msg3 = N2
en_msg3 = puKeyB.encrypt(msg3.encode())
s.send(en_msg3)
print('The message 3: "', msg3, '" is sent\n')

#(4)
msg4 = N2
en_msg4 = puKeyB.encrypt(msg4.encode())
s.send(en_msg4)
print('The message 4: "', msg4, '" is sent\n')


# receive text or image
# Uncommend line 83 and commend line 84 to receive text file

# file = open('server.txt','wb')
file = open('server.jpg','wb')
msg5 = s.recv(256)

while msg5.__contains__('ENDOFFILE'.encode()) != True:
    de_msg5 = prKeyA.decrypt(msg5)
    file.write(de_msg5)
    msg5 = s.recv(256)

file.close()
print('Image or text file is received')
b = s.recv(256)

s.close()
