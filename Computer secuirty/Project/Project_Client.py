import socket                   # Import socket module
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA3_256
from tools import *
import datetime


def main():

    password = ""   #prompts user for a password, to prevent others from using the workstation
    while password != "admin":
        password = input("Please enter your password\n")

    s = socket.socket()             # Create a socket object
    port = 60000                    # Reserve a port for your service.

    s.connect(('127.0.0.1', port))  # Connect to server
    
    PRA, PUA, ks = authentificate(s, "client") #authenticate the client
    
    while True:
        try: #Receive the purchase order information
            itemName = input("\nPlease state the name of the item\n")
            unitCost = input("What is the unit cost of one item?\n")
            amount = input("Please enter the amount that you're ordering\n")
            
            #Sign and timestamp the purchase order
            hash = SHA3_256.new(itemName.encode() + b',' + unitCost.encode() + b',' + amount.encode())
            signer = PKCS1_PSS.new(PRA)
            sig = signer.sign(hash)
            timestamp = ''.join(datetime.datetime.now().strftime('%S'))

            #Send the purchase order for approval
            msg = append_space_padding(itemName.encode() + b'|,|' + unitCost.encode() + b'|,|' + amount.encode() + b'|,|' + sig + b'|,|' + PUA.export_key() + b'|,|' + timestamp.encode()) #encrypts msg and the msg id
            msg = encrypt(msg,ks)
            s.sendall(len(msg).to_bytes(128,'big') + msg)
            print("Order Sent!")

        except KeyboardInterrupt:
            break

    s.shutdown(socket.SHUT_RDWR) #close mail server connection
    s.close()

if __name__ == "__main__":
	main()