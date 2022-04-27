from Crypto.Cipher import DES
from Crypto import Random

plaintext = input('The Plain text:')
key = 'abcasdda'
iv = Random.new().read(DES.block_size)

#Encryption
en_cipher = DES.new(key.encode(),DES.MODE_OFB,iv)
en_text = iv + en_cipher.encrypt(plaintext.encode())
print('\nThe encrypted message:',en_text,'\n')

#Decryption
de_cipher = DES.new(key.encode(), DES.MODE_OFB, iv)
de_text = de_cipher.decrypt(en_text[8:])
print('The decrypted message:',de_text.decode())