# -*- coding: utf-8 -*- 

import os, sys, subprocess, signal, base64, array, binascii, random, re
from subprocess import Popen, PIPE

import pyxed

# 1 for instructions, and invalid output
# 3 for instructions only
debug = 6

# REPLACE WITH ARG2
#filename = 'A5.py'
filename = 'codebreaker2.exe'
with open(filename, 'rb') as f:
    content = f.read()
binhex = binascii.hexlify(content);



#////////////////////////////////////////////////////////////////////HEX DUMP//////////////////////////////////////////////////////////////////////
# FLAG CREATION TO ARG 2, CHANGE TO FILE DUMP
'''
print ("ADDRESS	")
i = 0
while i < len(binhex):
	if(i%32==0):
		print (format(i/2, 'x').zfill(8)+ ": "), 
	sys.stdout.write(binhex[i])
	if(i%2==1):
		sys.stdout.write(" ")
	if(i%32==31):
		print ("")
	i += 1
'''
#////////////////////////////////////////////////////////////////////OBJ DUMP//////////////////////////////////////////////////////////////////////
# FLAG CREATION TO ARG 2, CHANGE TO FILE DUMP
'''
print ("ADDRESS	")
i = 0
while i < (len(binhex)-1):
	if(i%32==0):
		print( format(i/2, 'x').zfill(8)+ ": "), 
	hexstr = binhex[i]+binhex[i+1]
	#print (binhex[i]+binhex[i+1])
	#print( hexstr.decode("hex")),
	if( int(hexstr,16) > 15 and (int(hexstr,16) < 120 or int(hexstr,16) > 254)) :
		#print (int(hexstr,16)),
		print( unichr(int(hexstr,16))),
	else:
		print ("."),
	if(i%2==2):
		sys.stdout.write(" ")
	if(i%32==30):
		print ("")
	i += 2	
'''

#////////////////////////////////////////////////////////////////////INST DUMP//////////////////////////////////////////////////////////////////////
# FLAG CREATION TO ARG 3, Instruction Dump
binhex_begin = 0
xed = pyxed.Decoder()
xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
hexdig = "5531D289E58B4508568B750C538D58FF0FB60C16884C130183C20184C975F15B5E5DC3"
hexdig = binhex[binhex_begin:]
xed.itext = binascii.unhexlify(hexdig)
xed.runtime_address = 0x00000000

#/////////////////////////////////////////////////////////////////////FULLY RUNS INSTRUCTION FOR FULL BINARY
'''
while True:
	inst = xed.decode()
	if inst is None:
		break
	print (inst.dump_intel_format())

'''

#/////////////////////////////////////////////////////////////////////Run Instructions Byte by Byte to create a Answer Key
q = 0 # tracks header pointer
p = 2 # tracks tail pointer
# hex string to track for testing

#SET HEXDIG to file input
#hexdig = binhex

instr_key = dict()
bad_c = 0
#loop through until terminate where p == q 
while True:
	try:
		xed.itext = binascii.unhexlify(hexdig[q:p]) # decodes bytes between header and tail
		if(debug == 4):
			print (hexdig[q:p])
		if(q == len(hexdig)):
			break
		xed.runtime_address = 0x00000000 + q/2
		inst = xed.decode()							# decodes bytes between header and tail	
		instr_str = inst.dump_intel_format()
		if(debug == 2):
			print (" Address: " + instr_str[:8] + " Instruction: " + instr_str[9:])
		instr_key[instr_str[:8]]	= instr_str[9:]
		if(debug == 1):
			print (instr_str)							# dumps sucessful translation
		xed = pyxed.Decoder()
		xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
		xed.runtime_address = 0x00000000 + q/2
		q = p 										# move head to tail
		p = q + 2
		continue
	except:
		if(debug == 3):
			print ("Oops!  That was not a valid decode.  Try again...")
			print ("p: "+ str(p) + " q: " + str(q) + " | "+ hexdig[q:p])
			print ("LENGEHTH: " + str(len(hexdig[q:p])))
		xed = pyxed.Decoder()
		xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
		if(p-q>28):
			instr_key[str(q/2)]	= "BAD BYTE"
			bad_c +=1
			q+=2 
			p = q
		if(p <= len(hexdig)):
			p += 2
		else:
			break
		continue
	
#/////////////////////////////////////////////////////////////////////Given this answer key run same binary and pick random start point
#/////////////////////////////////////////////////////////////////////Find number of bad instructions before realigned
# reset starting conditions
q = 0 # tracks header pointer
p = 2 # tracks tail pointer

#count number of bad bytes
instruction_offset = 0
#random starting point to determine realignment calculation
q = random.randint(0, len(hexdig)-1)
if q%2 == 1:
	q+=1
intial_q = q
p = q+2 

if intial_q == len(hexdig):
	instruction_offset = intial_q/2

#create a dictionary for comparison
instr_test = dict()
print ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
print ("STARTING FILE AT " + str(q/2))

if q < len(hexdig):
	while True:
		try:
			xed.itext = binascii.unhexlify(hexdig[q:p]) # decodes bytes between header and tail
			if(debug== 4):
				print (hexdig[q:p])
			if(q == len(hexdig)):
				break
			xed.runtime_address = 0x00000000 + q/2
			inst = xed.decode()							# decodes bytes between header and tail	
			instr_str = inst.dump_intel_format()
			if(debug== 2):
				print (" Address: " + instr_str[:8] + " Instruction: " + instr_str[9:])
			instr_test[instr_str[:8]]	= instr_str[9:]
			if(debug == 1):
				print (instr_str)							# dumps sucessful translation
			xed = pyxed.Decoder()
			xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
			xed.runtime_address = 0x00000000 + q/2
			q = p 										# move head to tail
			p = q + 2
			continue
		except:
			if(debug == 3):
				print ("Oops!  That was not a valid decode.  Try again...")
				print ("p: "+ str(p) + " q: " + str(q) + " | "+hexdig[q:p])
				print ("LENGEHTH: " + str(len(hexdig[q:p])))
			xed = pyxed.Decoder()
			xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
			if(p-q>28):
				instr_key[str(q/2)]	= "BAD BYTE"
				q+=2
				p = q
			if(p <= len(hexdig)):
				p += 2
			else:
				break
			continue
if(debug < 5):
	# A KEY OF CORRECT PARSING TO COMPARE TO
	print ("CONTENTS OF KEY DICTONARY")
	for key in sorted(instr_key):
		print ("%s: %s" % (key,instr_key[key]))

found_align = 0
if(debug < 5):
	print ("CONTENTS OF TEST DICTONARY")

for key in sorted(instr_test):
	if instr_key.has_key(key) and not(found_align):
		found_align = 1
		instruction_offset = int(key,16)
	if(debug < 5):
		print ("%s: %s" % (key,instr_test[key]))
print ("intial q " + str(intial_q/2) + " inst offset "+ str(instruction_offset))
print ("NUMBER OF BYTES TO ALIGNMENT: " + str(instruction_offset-intial_q/2) + " BYTES. ")
print ("NUMBER OF INVALID BYTES: " + str(bad_c) +".")	

