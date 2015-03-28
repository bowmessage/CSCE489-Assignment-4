# -*- coding: utf-8 -*- 
# top right
import os, sys, subprocess, signal, base64, array, binascii
from subprocess import Popen, PIPE

import pyxed

# 1 for instructions, and invalid output
# 3 for instructions only

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
'''
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

#////////////////////////////////////////////////////////////////////INST DUMP//////////////////////////////////////////////////////////////////////
# FLAG CREATION TO ARG 3, Instruction Dump

xed = pyxed.Decoder()
xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
hexdig = "5531D289E58B4508568B750C538D58FF0FB60C16884C130183C20184C975F15B5E5DC3"
xed.itext = binascii.unhexlify(hexdig)
xed.runtime_address = 0x00000000

#/////////////////////////////////////////////////////////////////////FULLY RUNS INSTRUCTION FOR FULL BINARY
'''
while True:
	inst = xed.decode()
	if inst is None:
		break
	print inst.dump_intel_format()

'''
q = 0 # tracks header pointer
p = 2 # tracks tail pointer
# hex string to track for testing

#random starting point to determine realignment calculation
#q = 4

#SET HEXDIG to file input

instr_key = dict()

#loop through until terminate where p == q 
while True:
	try:
		xed.itext = binascii.unhexlify(hexdig[q:p]) # decodes bytes between header and tail
		#print hexdig[q:p]
		if(p == len(hexdig)):
			break
		xed.runtime_address = 0x00000000 + q/2
		inst = xed.decode()							# decodes bytes between header and tail	
		instr_str = inst.dump_intel_format()
		if(debug%2 == 0):
			print " Address: " + instr_str[:8] + " Instruction: " + instr_str[9:]
		instr_key[instr_str[:8]]	= instr_str[9:]
		if(debug%2 == 1):
			print instr_str							# dumps sucessful translation
		xed = pyxed.Decoder()
		xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
		xed.runtime_address = 0x00000000 + q/2
		q = p 										# move head to tail
		p = q + 2
		continue
	except:
		if(debug == 1):
			print "Oops!  That was not a valid decode.  Try again..."
			print "p: "+ str(p) + " q: " + str(q) + hexdig[q:p]
		xed = pyxed.Decoder()
		xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
		if(p <= len(hexdig)):
			p += 2
		else:
			break
		continue

# A KEY OF CORRECT PARSING TO COMPARE TO