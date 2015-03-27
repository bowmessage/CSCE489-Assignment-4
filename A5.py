# -*- coding: utf-8 -*- 
# top right
import os, sys, subprocess, signal, base64, array, binascii
from subprocess import Popen, PIPE

# REPLACE WITH ARG2
#filename = 'A5.py'
filename = 'codebreaker2.exe'
with open(filename, 'rb') as f:
    content = f.read()
binhex = binascii.hexlify(content);



#////////////////////////////////////////////////////////////////////HEX DUMP//////////////////////////////////////////////////////////////////////
# FLAG CREATION TO ARG 2, CHANGE TO FILE DUMP
'''
print "ADDRESS	"
i = 0
while i < len(binhex):
	if(i%32==0):
		print format(i/2, 'x').zfill(8)+ ": ", 
	sys.stdout.write(binhex[i])
	if(i%2==1):
		sys.stdout.write(" ")
	if(i%32==31):
		print ""
	i += 1
'''
#////////////////////////////////////////////////////////////////////OBJ DUMP//////////////////////////////////////////////////////////////////////
# FLAG CREATION TO ARG 2, CHANGE TO FILE DUMP
print "ADDRESS	"
i = 0
while i < (len(binhex)-1):
	if(i%32==0):
		print format(i/2, 'x').zfill(8)+ ": ", 
	hexstr = binhex[i]+binhex[i+1]
	#print binhex[i]+binhex[i+1]
	#print hexstr.decode("hex"),
	if( int(hexstr,16) > 15 and (int(hexstr,16) < 120 or int(hexstr,16) > 254)) :
		#print int(hexstr,16),
		print unichr(int(hexstr,16)),
	else:
		print ".",
	if(i%2==2):
		sys.stdout.write(" ")
	if(i%32==30):
		print ""
	i += 2	
'''

# first see which directory currently working from
print "Current working dir : %s" % os.getcwd() 

#establish key for final to solve
str2 = "JnCkOLoOVmim2dP1X1JnyLqDXOhdCWZUGRHQ8Y/OAZw+9/HC4a3t2l+QzTNZcTfr0x8Q+lN3jjjbfUzlWwNJCNAQfJUKCjQmcZbZaeBbzbGytn8X5RD8IGLZtmCM38U2K8z1Ranv0RdWqUmCbOqhAmFlNOk/dwOa/hk6BPzMf3moDots4nLP/cFDrc2bPL8rEIy6pgAGPN98on6f6Ig0Vp7ATuK6GRq1tDHzMihC+tn+ZBndyGP5KoU3BnqZI8oGaEfK5ikK5MazUzm3AIx1WQRrINJYNwIlBhbPe5FwzrYuQGhIr5jedKQCn8QzBUjmRVXhRUgKSlcqqiS+/X1IVqbWCLHPhg=="	
	
# create a blank slate
#key = ""
#j = 0
#while j <(220+42):
#		key+="_"
#		j+=1

#base = list(key) 
ascii = 30
ascii = 'a'
#while ascii < 255:
while ascii < 'b':
	s = ""
	
	#create a sample message
	i = 0
	while i <220:
		s+=ascii
	#	s+=chr(ascii)
		i+=1
	
	#open a program start of loop
	FNULL = open(os.devnull, 'w')
	p1 = Popen(["codebreaker2_try2.exe","-X"], stdin=PIPE, stdout = FNULL)

	#pipe in the three arguements
	p1.stdin.write( "Tier3_Codebreakers\n" )
	p1.stdin.write( "a\n")
	p1.stdin.write( s+"\n" )
	p1.wait()
	############################################################My Method
	#fo = open("msg")
	#str = fo.read();					#current attempts base64
	#data = base64.b64decode(str[18:])	#current attempts decoded
	#data2 =  base64.b64decode(str2)		#goals decoded
	#	
	#k = 0
	#while k < len(data2):
	#	if ord(data[k]) == ord(data2[k]):
	#		base[k] = chr(ascii)
	#	k+=1	
	# data is searching for crypt
	# data2 is current msg crypt
	# str 3 is plain of current
	############################################################James Method
	#open new message and compare to key
	fo = open("tier4_challenge_msg")
	str = fo.read();
	print str[18:]
	data = base64.b64decode(str[18:])
	fo.close()
	fo = open("msg")
	str2 = fo.read()
	print str2[18:]
	data2 =  base64.b64decode(str2[18:])
	str3 = "---MESSAGE BEGIN---\n"+s+"---MESSAGE END---\n"
	
	j = 0
	while j < len(str3):
		print (ord(data2[j])^ord(str3[j]))
		#print chr(ord(data[j])^(ord(data2[j])^ord(str3[j])))
		j+=1
	#####################################################################################
	fo.close();
	ascii = ord(ascii)
	ascii+=1
	ascii = chr(ascii)
#print ''.join(base)
'''

