from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#generate public and private key
rsa = RSA.generate(2048, Random.new().read)
pr = rsa.exportKey()
pu = rsa.publickey().exportKey()

#Get the plaintext from the user
plaintext = input('The plain Text:')

#Encryption
pu_key = RSA.importKey(pu)
pu_key = PKCS1_OAEP.new(pu_key)
en_text = pu_key.encrypt(plaintext.encode())
print('\nThe encrypted message:',en_text,'\n')

#Decryption
pr_key = RSA.importKey(pr)
pr_key = PKCS1_OAEP.new(pr_key)
de_text = pr_key.decrypt(en_text)
print('The decrypted message:',de_text.decode())
