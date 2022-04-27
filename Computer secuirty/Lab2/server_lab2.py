import socket                   # Import socket module
from Crypto.Cipher import DES
from Crypto import Random


port = 60000                    # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
print(host)
s.bind(('127.0.0.1', port))            # Bind to the port
s.listen(5)                     # Now wait for client connection.

Ks = 'RYERSON'
Km = 'NETWORK SECURITY'
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

while True:
    conn, addr = s.accept()     # Establish connection with client.
    
    #The received message 1
    IDa = conn.recv(20)
    IDa = IDa.decode("utf-8")
    print('The message 1 is:',IDa,'\n')

    #The ciphertext of message 2
    msg2 = Ks + '||'+ IDa + '||' + IDb
    plaintext_pad = append_space_padding(msg2)
    en_text2 = encrypt(msg2,Km[0:8].encode())
    conn.send(en_text2)
    print('The ciphertext of message 2 is:',en_text2,'\n')

    #The received ciphertext of message 3
    msg3 = conn.recv(200)
    print('Recieved the ciphertext of message 3 is:',msg3,'\n')
    de_text3 = decrypt(msg3, append_space_padding(Ks).encode())
    #The decrypted message 3
    plaintext3 = remove_space_padding(de_text3)
    print('The decrypted message 3:',plaintext3,'\n\n')

    conn.close()
