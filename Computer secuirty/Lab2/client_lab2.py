import socket                   # Import socket module
from Crypto.Cipher import DES
from Crypto import Random

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

s = socket.socket()             # Create a socket object
port = 60000                    # Reserve a port for your service.
Km = "NETWORK SECURITY"
IDa = "INITIATOR A"

s.connect(('127.0.0.1', port))
print('Connected to the host\n\n')


#Cleartext of message 1
s.send(IDa.encode())
print('The cleartext,',IDa,',is sent\n\n')

#The recieved ciphertext of message 2
msg2 = s.recv(200)
print('Recieved the ciphertext of message 2 is:',msg2)
de_text2 = decrypt(msg2, Km[0:8].encode())
#The decrypted message 2
plaintext2 = remove_space_padding(de_text2)
print('The decrypted message 2:',plaintext2,'\n\n')

#Send the message 3 to server
Ks = de_text2[0:7]
IDb = de_text2[22:]
plaintext_pad = append_space_padding(IDb)
Ks_pad = append_space_padding(Ks)
en_text3 = encrypt(plaintext_pad, Ks_pad.encode())
s.send(en_text3)

s.close()
