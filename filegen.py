from random import randint
import os,binascii, random

filesize = random.randint(10000, 25000)

if (filesize%2 == 1):
	filesize+=1
binaryhex = binascii.b2a_hex(os.urandom(filesize))
print binaryhex
	
with open("RandomDump5.txt", "wb") as myfile:
	myfile.write(binascii.unhexlify(binaryhex))