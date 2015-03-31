# -*- coding: utf-8 -*- 

import os, sys, subprocess, signal, base64, array, binascii, random, re, math
from subprocess import Popen, PIPE
import pyxed

import numpy as np
import matplotlib.pyplot as plt

from PySide import QtCore, QtGui



# 1 for instructions, and invalid output
# 3 for instructions only
debug = 5
#////////////////////////////////////////////////////////////////////FUNCTIONS//////////////////////////////////////////////////////////////////////
def reverse_hex(original):
	hex1= original[0] + original[1]
	hex2= original[2] + original[3]
	hex3= original[4] + original[5]
	hex4= original[6] + original[7]
	return hex4 + hex3 + hex2 + hex1

def decode_main(filename):
	out = ""
	#////////////////////////////////////////////////////////////////////MAIN//////////////////////////////////////////////////////////////////////

	# REPLACE WITH ARG2
	#filename = 'A5.py'
	with open(filename, 'rb') as f:
	    content = f.read()
	binhex = binascii.hexlify(content);

	m = re.search('50450000', binhex)
	out += "\n" +  hex(int(m.start())/2)
	# reading location of code
	out += "\n" +  "code:"
	out += "\n" +  binhex[m.start()+44*2:m.start()+44*2+8]
	code = reverse_hex(binhex[m.start()+44*2:m.start()+44*2+8])
	out += "\n" +  code
	# reading location of data
	out += "\n" +  "data:"
	out += "\n" +  binhex[m.start()+48*2:m.start()+48*2+8]
	data = reverse_hex(binhex[m.start()+48*2:m.start()+48*2+8])
	out += "\n" +  data

	#////////////////////////////////////////////////////////////////////HEX DUMP//////////////////////////////////////////////////////////////////////
	# FLAG CREATION TO ARG 2, CHANGE TO FILE DUMP
	'''
	out += "\n" +  ("ADDRESS	")
	i = 0
	while i < len(binhex[0:1000]):
		if(i%32==0):
			out += "\n" +  (format(i/2, 'x').zfill(8)+ ": "), 
		sys.stdout.write(binhex[i])
		if(i%2==1):
			sys.stdout.write(" ")
		if(i%32==31):
			out += "\n" +  ("")
		i += 1
	'''
	#////////////////////////////////////////////////////////////////////OBJ DUMP//////////////////////////////////////////////////////////////////////
	# FLAG CREATION TO ARG 2, CHANGE TO FILE DUMP
	'''
	out += "\n" +  ("ADDRESS	")
	i = 0
	while i < (len(binhex)-1):
		if(i%32==0):
			out += "\n" + ( format(i/2, 'x').zfill(8)+ ": "), 
		hexstr = binhex[i]+binhex[i+1]
		#out += "\n" +  (binhex[i]+binhex[i+1])
		#out += "\n" + ( hexstr.decode("hex")),
		if( int(hexstr,16) > 15 and (int(hexstr,16) < 120 or int(hexstr,16) > 254)) :
			#out += "\n" +  (int(hexstr,16)),
			out += "\n" + ( unichr(int(hexstr,16))),
		else:
			out += "\n" +  ("."),
		if(i%2==2):
			sys.stdout.write(" ")
		if(i%32==30):
			out += "\n" +  ("")
		i += 2	
	'''

	#////////////////////////////////////////////////////////////////////INST DUMP//////////////////////////////////////////////////////////////////////
	# FLAG CREATION TO ARG 3, Instruction Dump
	binhex_begin = 0

	# LOOK FOR WHERE CODE SECTION BEGINS
	if(m.start()<500):
		binhex_begin = int(m.start())/2
		k = int(m.start())
		out += "\n" +  "PE HEADER: " + binhex[k: k+8]
		k += 8
		out += "\n" +  "MACHINE: " + binhex[k:k+4]
		k += 4 
		out += "\n" +  "NUMBER OF SECTIONS: " + binhex[k:k+4]
		k += 4
		out += "\n" +  "TIMEDATESTAMP: " + binhex[k:k+8]
		k += 8
		out += "\n" +  "SYMBOL TABLE ADDRESS: " + binhex[k:k+8]
		k+=8
		out += "\n" +  "NUMBER OF SYMBOLS: " + binhex[k:k+8]
		k+=8
		out += "\n" +  "Optional Header Size: " + binhex[k:k+4]
		k += 4 
		out += "\n" +  "CHARACTERISTICs: " + binhex[k:k+4]
		k += 4
		out += "\n" +  "Magic Number: " + binhex[k:k+4]
		k += 4
		out += "\n" +  "Major Linker Version: " + binhex[k:k+2]
		k += 2
		out += "\n" +  "Minor Linker Version: " + binhex[k:k+2]
		k += 2
		out += "\n" +  "Size Of Code: " + binhex[k:k+8]
		k+=8
		out += "\n" +  "Size Of Initialized Data: " + binhex[k:k+8]
		k+=8
		out += "\n" +  "Size of Uninitialized Data: " + binhex[k:k+8]
		k+=8
		out += "\n" +  "Entry Point Address: " + binhex[k:k+8]
		k+=8
		out += "\n" +  "Base Of Code: " + binhex[k:k+8]
		k+=8
		out += "\n" +  "Base of Data: " + binhex[k:k+8]
		k+=8
		
	out += "\n" +  str(int(str(int(reverse_hex(binhex[m.start()+48*2:m.start()+48*2+8]))),16))
	data_begin_addr =  int(str(int(reverse_hex(binhex[m.start()+48*2:m.start()+48*2+8]))),16)*2
	binhex_code = binhex[data_begin_addr:]
	out += "\n" +  str(int(str(int(reverse_hex(binhex[m.start()+44*2:m.start()+44*2+8]))),16))
	code_begin_addr = int(str(int(reverse_hex(binhex[m.start()+44*2:m.start()+44*2+8]))),16)*2
	#binhex_code = binhex[code_begin_addr:data_begin_addr]
	binhex_code = binhex[code_begin_addr:code_begin_addr+0x3fa00]
	xed = pyxed.Decoder()
	xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
	hexdig = "5531D289E58B4508568B750C538D58FF0FB60C16884C130183C20184C975F15B5E5DC3"
	hexdig = binhex_code
	xed.itext = binascii.unhexlify(hexdig)
	xed.runtime_address = 0x00000000

	#/////////////////////////////////////////////////////////////////////FULLY RUNS INSTRUCTION FOR FULL BINARY
	'''
	while True:
		inst = xed.decode()
		if inst is None:
			break
		out += "\n" +  (inst.dump_intel_format())

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
				out += "\n" +  (hexdig[q:p])
			if(q == len(hexdig)):
				break
			xed.runtime_address = 0x00000000 + q/2
			inst = xed.decode()							# decodes bytes between header and tail	
			instr_str = inst.dump_intel_format()
			if(debug == 2):
				out += "\n" +  " Address: " + instr_str[:8] + " Instruction: " + instr_str[9:]
			instr_key[instr_str[:8]]	= instr_str[9:]
			if(debug == 1):
				out += "\n" +  (instr_str)							# dumps sucessful translation
			xed = pyxed.Decoder()
			xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
			xed.runtime_address = 0x00000000 + q/2
			q = p 										# move head to tail
			p = q + 2
			continue
		except:
			if(debug == 3):
				out += "\n" +  "Oops!  That was not a valid decode.  Try again..."
				out += "\n" +  "p: "+ str(p) + " q: " + str(q) + " | "+ hexdig[q:p]
				out += "\n" +  "LENGEHTH: " + str(len(hexdig[q:p]))
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
	if(debug < 5):
		out += "\n" +  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
		out += "\n" +  "STARTING FILE AT " + str(q/2)

	if q < len(hexdig):
		while True:
			try:
				xed.itext = binascii.unhexlify(hexdig[q:p]) # decodes bytes between header and tail
				if(debug== 4):
					out += "\n" +  hexdig[q:p]
				if(q == len(hexdig)):
					break
				xed.runtime_address = 0x00000000 + q/2
				inst = xed.decode()							# decodes bytes between header and tail	
				instr_str = inst.dump_intel_format()
				if(debug== 2):
					out += "\n" +  " Address: " + instr_str[:8] + " Instruction: " + instr_str[9:]
				instr_test[instr_str[:8]]	= instr_str[9:]
				if(debug == 1):
					out += "\n" +  instr_str							# dumps sucessful translation
				xed = pyxed.Decoder()
				xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
				xed.runtime_address = 0x00000000 + q/2
				q = p 										# move head to tail
				p = q + 2
				continue
			except:
				if(debug == 3):
					out += "\n" +  "Oops!  That was not a valid decode.  Try again..."
					out += "\n" +  "p: "+ str(p) + " q: " + str(q) + " | "+hexdig[q:p]
					out += "\n" +  "LENGEHTH: " + str(len(hexdig[q:p]))
				xed = pyxed.Decoder()
				xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
				if(p-q>28):
					instr_key[str(format(q/2, 'x').zfill(8)) ]	= "BAD BYTE"
					q+=2
					p = q
				if(p <= len(hexdig)):
					p += 2
				else:
					break
				continue
	if(debug <= 5):
		# A KEY OF CORRECT PARSING TO COMPARE TO
		out += "\n" +  "CONTENTS OF KEY DICTONARY"
		f = open('Assembly.txt','w')
		for key in sorted(instr_key):
			f.write("%s: %s\n" % (key,instr_key[key]))
		f.close()

	found_align = 0
	if(debug < 5):
		out += "\n" +  "CONTENTS OF TEST DICTONARY"

	for key in sorted(instr_test):
		if instr_key.has_key(key) and not(found_align):
			found_align = 1
			instruction_offset = int(key,16)
		if(debug < 5):
			out += "\n" +  "%s: %s" % (key,instr_test[key])

	out += "\n" +  "NUMBER OF BYTES TO ALIGNMENT: " + str(instruction_offset-intial_q/2) + " BYTES. "
	out += "\n" +  "NUMBER OF INVALID BYTES: " + str(bad_c) +"."
	return out


def autolabel(rects):
    # attach some text labels
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x()+rect.get_width()/2., 1.05*height, '%d'%int(height),
                ha='center', va='bottom')

def showgraph():

	opcode_histogram = dict()
	for key in instr_key:
		opcode = re.search("^([\w\-]+)",instr_key[key]).group(0)
		if opcode in opcode_histogram:
			opcode_histogram[opcode] += 1
		else:
			opcode_histogram[opcode] = 1

	N = len(opcode_histogram)


	ind = np.arange(N)  # the x locations for the groups
	width = 0.35       # the width of the bars

	fig, ax = plt.subplots()
	rects1 = ax.bar(ind, opcode_histogram.values(), width, color='r')

	# add some text for labels, title and axes ticks
	ax.set_ylabel('Instructions')
	ax.set_title('Instructions by opcode')
	ax.set_xticks(ind+width)

	opcodes = opcode_histogram.keys()
	ax.set_xticklabels( opcodes )

	#ax.legend( (rects1[0]), ('Instructions') )



	autolabel(rects1)

	plt.show()

if __name__ == '__main__':

    app = QtGui.QApplication(sys.argv)
    mainWin = Window()
    mainWin.show()
    sys.exit(app.exec_())