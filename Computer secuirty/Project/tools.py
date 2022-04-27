from Crypto.Cipher import DES,PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
import socket 
import datetime

def append_space_padding(plaintext, blocksize=8):
    # pad the plaintext at the end so that the length is a multiple of the blocksize
    padded_plaintext = pad(plaintext,blocksize)
    return padded_plaintext

def remove_space_padding(str, blocksize=8):
    # Unpad the decrypted bytestream
    unpadded_text = unpad(str,blocksize)
    unpadded_text = unpadded_text[8:]

    return unpadded_text

def encrypt(Plaintext_pad, key):
    # Encrypt the padded plaintext using single DES
    cipher = DES.new(key,DES.MODE_CBC)
    cipher_text = cipher.encrypt(Plaintext_pad)

    return cipher.iv + cipher_text


def decrypt(ciphertext, key):
    # Decrypt the cipher text using single DES
    cipher = DES.new(key,DES.MODE_CBC)
    plain_text = cipher.decrypt(ciphertext)

    return plain_text

def nonce(): #generates a random nonce
    return Random.get_random_bytes(8)

def authentificate(s,id):
    print("Authentication in progress...")
    #initiator side of authentification
    PUB = b''
    PRA = RSA.generate(1024)    #Generate RSA keys for authentiification and signature
    PUA = PRA.public_key()

    #Exchange Public keys 
    s.sendall(PUA.export_key())
    PUB = s.recv(1024)
    PUB = RSA.import_key(PUB)

    #Create encryption and decrytion RSA ciphers
    authcipher_encrypt = PKCS1_OAEP.new(PUB)
    authcipher_decrypt = PKCS1_OAEP.new(PRA)

    #Authentification
    # Send Message 1, Client ID + Nonce
    N1 = Random.get_random_bytes(8)
    msg1 = N1 + b'|,|' + id.encode()
    msg1 = authcipher_encrypt.encrypt(msg1)
    s.sendall(msg1)


    # Receive Authentification Message 2
    msg2 = s.recv(128, socket.MSG_WAITALL)
    msg2 = authcipher_decrypt.decrypt(msg2)
    n1, n2 = msg2.split(b'|,|') # Retrieve N1 and N2 from authentification msg 2
    if n1 != N1:
        raise ValueError("Nonce received does not match nonce sent, authentification failed")

    #Send Authentification Message 3
    msg3 = n2
    msg3 = authcipher_encrypt.encrypt(msg3)
    s.sendall(msg3)

    #Send Session Key and Signature in Authentification Message 4
    ks = Random.get_random_bytes(8)
    
    hash = SHA3_256.new(ks)
    signer = PKCS1_PSS.new(PRA)
    sig = signer.sign(hash)
    msg4 = ks + b'|,|' + sig
    msg4 = authcipher_encrypt.encrypt(msg4)
    s.sendall(msg4)
    
    print("\nAuthentification successful")

    return PRA, PUA, ks

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
        msg = decrypt(msg,key) #decrypt msg
        msg = remove_space_padding(msg)
        if msg.count(b'|,|') == 5: #retreive msg elements
            name, cost, amount, sig1, PUP, timestamp = msg.split(b'|,|')
        else:
            name, cost, amount, sig1, PUP, sig2, PUS, timestamp = msg.split(b'|,|')
        timestamp = (int) (timestamp.decode())
        teststamp = (int) (''.join(datetime.datetime.now().strftime('%S')))
        if ((teststamp - timestamp) < 5): #validate timestamp
            hash = SHA3_256.new(name + b'|,|' + cost + b'|,|' + amount)
            PU = RSA.import_key(PUP)
            ver = PKCS1_PSS.new(PU)
            ver.verify(hash,sig1)   #verify client signature
            if msg.count(b'|,|') == 7:
                PS = RSA.import_key(PUS)
                ver = PKCS1_PSS.new(PS)
                ver.verify(hash,sig2) #verify supervisor signature, if present
                q.put(name + b'|,|' + cost + b'|,|' + amount + b'|,|' + sig1 + b'|,|' + PUP + b'|,|' + sig2 + b'|,|' + PUS)
            else:
                q.put(name + b'|,|' + cost + b'|,|' + amount + b'|,|' + sig1 + b'|,|' + PUP)
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