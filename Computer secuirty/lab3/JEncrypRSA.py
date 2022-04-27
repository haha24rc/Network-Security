from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from sys import getsizeof

#generate public and private key
rsa = RSA.generate(2048, Random.new().read)
pr = rsa.exportKey()
pu = rsa.publickey().exportKey()

#Get the plaintext from the user
plaintext = input('The plain Text:')
a = 'Design your UI (user interface) for the secure chat solution. Your UI must allow the TA to see what message is actually sent and received over the wire at each point in the communication processes. Both chat client and server must show the following messages: '
a = a.encode()
b = a[0:206]
plaintext = b
print(getsizeof(plaintext))
#Encryption
pu_key = RSA.importKey(pu)
pu_key = PKCS1_OAEP.new(pu_key)
en_text = pu_key.encrypt(plaintext)
print('\nThe encrypted message:',en_text,'\n')

#Decryption
pr_key = RSA.importKey(pr)
pr_key = PKCS1_OAEP.new(pr_key)
de_text = pr_key.decrypt(en_text)
print('The decrypted message:',de_text.decode())
