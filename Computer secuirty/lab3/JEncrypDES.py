import random
import sys

a = 'Aesign your UI (user interface) for the secure chat solution. Your UI must allow the TA to see what message is actually sent and received over the wire at each point in the communication processes. Both chat client and server must show the following messages: '
c = a.encode()
b = a[0:206].encode()
print(sys.getsizeof(b),' ',b)
d = c[0:206]
print(d)