# -*- coding: utf-8 -*- 

import os, sys, subprocess, signal, base64, array, binascii, random, re, math
from subprocess import Popen, PIPE
import pyxed, pydasm, pefile

import numpy as np
import matplotlib.pyplot as plt

from PySide import QtCore, QtGui



# 1 for instructions, and invalid output
# 3 for instructions only
debug = -1
#////////////////////////////////////////////////////////////////////FUNCTIONS//////////////////////////////////////////////////////////////////////
def reverse_hex(original):
	hex1= original[0] + original[1]
	hex2= original[2] + original[3]
	hex3= original[4] + original[5]
	hex4= original[6] + original[7]
	return hex4 + hex3 + hex2 + hex1
	
#////////////////////////////////////////////////////////////////////MAIN//////////////////////////////////////////////////////////////////////

def decode_main(filename):
	out = ""
	#////////////////////////////////////////////////////////////////////MAIN//////////////////////////////////////////////////////////////////////

	#filename = 'A5.py'
	with open(filename, 'rb') as f:
	    content = f.read()
	binhex = binascii.hexlify(content);

	m = re.search('50450000', binhex)
	if m is not None:
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
	
	hex_dump = open('Hex_Dump.txt','w')
	i = 0
	while i < len(binhex):
		if(i%32==0):
			hex_dump.write(format(i/2, 'x').zfill(8)+ ": ") 
		hex_dump.write(binhex[i])
		if(i%2==1):
			hex_dump.write(" ")
		if(i%32==31):
			hex_dump.write("\n")
		i += 1
	hex_dump.close()
	#////////////////////////////////////////////////////////////////////OBJ DUMP//////////////////////////////////////////////////////////////////////
	# FLAG CREATION TO ARG 2, CHANGE TO FILE DUMP
	
	ascii_dump = open('Ascii_Dump.txt','w')
	i = 0
	while i < (len(binhex)-1):
		if(i%32==0):
			ascii_dump.write( format(i/2, 'x').zfill(8)+ ": ") 
		hexstr = binhex[i]+binhex[i+1]
		if( int(hexstr,16) > 15 and (int(hexstr,16) < 254 or int(hexstr,16) > 254)) :
			ascii_dump.write( unichr(int(hexstr,16)).encode('utf8'))
		else:
			ascii_dump.write(".")
		if(i%2==2):
			ascii_dump.write(" ")
		if(i%32==30):
			ascii_dump.write("\n")
		i += 2	
	ascii_dump.close()

	#////////////////////////////////////////////////////////////////////INST DUMP//////////////////////////////////////////////////////////////////////
	# FLAG CREATION TO ARG 3, Instruction Dump
	binhex_begin = 0
	code_size = "0"
	code_base = "0"
	image_base = "0"
	if m is not None:
		print(m.start())
		# LOOK FOR WHERE CODE SECTION BEGINS
		if(m.start()<1024):
			binhex_begin = int(m.start())/2
			k = int(m.start())
			out += "\n" +  "PE HEADER: " + reverse_hex(binhex[k: k+8])
			k += 8
			out += "\n" +  "MACHINE: " + binhex[k+2:k+4] + binhex[k:k+2]
			k += 4 
			out += "\n" +  "NUMBER OF SECTIONS: " + binhex[k+2:k+4] + binhex[k:k+2]
			k += 4
			out += "\n" +  "TIMEDATESTAMP: " + reverse_hex(binhex[k:k+8])
			k += 8
			out += "\n" +  "SYMBOL TABLE ADDRESS: " + reverse_hex(binhex[k:k+8])
			k+=8
			out += "\n" +  "NUMBER OF SYMBOLS: " + reverse_hex(binhex[k:k+8])
			k+=8
			out += "\n" +  "Optional Header Size: " + binhex[k+2:k+4] + binhex[k:k+2]
			k += 4 
			out += "\n" +  "CHARACTERISTICs: " + binhex[k+2:k+4] + binhex[k:k+2]
			k += 4
			out += "\n" +  "Magic Number: " + binhex[k+2:k+4] + binhex[k:k+2]
			k += 4
			out += "\n" +  "Major Linker Version: " + binhex[k:k+2]
			k += 2
			out += "\n" +  "Minor Linker Version: " + binhex[k:k+2]
			k += 2
			code_size = reverse_hex(binhex[k:k+8])
			out += "\n" +  "Size Of Code: " + reverse_hex(binhex[k:k+8])
			k+=8
			out += "\n" +  "Size Of Initialized Data: " + reverse_hex(binhex[k:k+8])
			k+=8
			out += "\n" +  "Size of Uninitialized Data: " + reverse_hex(binhex[k:k+8])
			k+=8
			out += "\n" +  "Entry Point Address: " + reverse_hex(binhex[k:k+8])
			k+=8
			code_base = reverse_hex(binhex[k:k+8])
			out += "\n" +  "Base Of Code: " + code_base
			k+=8
			out += "\n" +  "Base of Data: " + reverse_hex(binhex[k:k+8])
			k+=8
			image_base = reverse_hex(binhex[k:k+8])
			out += "\n" +  "IMAGE BASE: " + image_base
			k+=8
	data_begin_addr = len(binhex)-1
	code_begin_addr = 0
	if(m is not None):
		print int(reverse_hex(binhex[m.start()+48*2:m.start()+48*2+8]),16)
		data_begin_addr =  int(reverse_hex(binhex[m.start()+48*2:m.start()+48*2+8]),16)*2
		binhex_code = binhex[data_begin_addr:]
		print  int(reverse_hex(binhex[m.start()+44*2:m.start()+44*2+8]),16)
		code_begin_addr = int(reverse_hex(binhex[m.start()+44*2:m.start()+44*2+8]),16)
	#binhex_code = binhex[code_begin_addr:data_begin_addr]
	#binhex_code = binhex[code_begin_addr:code_begin_addr+0x3fa00]
	#code_begin_addr = 2080
	#code_begin_addr = 4096*2
	binhex_code = binhex[code_begin_addr*2:code_begin_addr*2+int(code_size,16)*2]
	if m is None:
		binhex_code = binhex
	xed = pyxed.Decoder()
	xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
	hexdig = binhex_code
	xed.itext = binascii.unhexlify(hexdig)
	xed.runtime_address = 0x00000000 + 4096

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
			xed.runtime_address = 0x00000000 + q/2 + int(image_base, 16) + code_begin_addr
			inst = xed.decode()							# decodes bytes between header and tail	
			instr_str = inst.dump_intel_format()
			if(debug == 2):
				out += "\n" +  " Address: " + instr_str[:8] + " Instruction: " + instr_str[9:]
			instr_key[instr_str[:8]]	= instr_str[9:]
			if(debug == 1):
				out += "\n" +  (instr_str)							# dumps sucessful translation
			xed = pyxed.Decoder()
			xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
			xed.runtime_address = 0x00000000 + q/2 + int(image_base, 16) + code_begin_addr
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
				xed.runtime_address = 0x00000000 + q/2 + int(image_base, 16) + code_begin_addr
				inst = xed.decode()							# decodes bytes between header and tail	
				instr_str = inst.dump_intel_format()
				if(debug== 2):
					out += "\n" +  " Address: " + instr_str[:8] + " Instruction: " + instr_str[9:]
				instr_test[instr_str[:8]]	= instr_str[9:]
				if(debug == 1):
					out += "\n" +  instr_str							# dumps sucessful translation
				xed = pyxed.Decoder()
				xed.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32, pyxed.XED_ADDRESS_WIDTH_32b)
				xed.runtime_address = 0x00000000 + q/2 + int(image_base, 16) + code_begin_addr
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
				
	if m is not None:
		#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		pe =  pefile.PE(filename)
		ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		starting_code = str(int(code_base) + int(image_base))
		ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
		data = pe.get_memory_mapped_image()[ep-(ep_ava - (int(starting_code,16))):ep+0xffffffff]
		offset = 0
		p = open('Assembly_pefile.txt','w')
		while offset < len(data):
			i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
			if (pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset) is not None): 
				p.write(str(format((int(starting_code,16))+offset,'x' ).zfill(8))+": "+pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)+"\n")
				#out += "\n" +  "one"
				offset += i.length
			else:
				offset += 1
		p.close()
		
		pe =  pefile.PE(filename)
		ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		starting_code = str(int(code_base) + int(image_base))
		ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
		n = random.randint(0, int(code_size,16)-1)
		if n%2 == 1:
			n+=1
		print "N: " + hex(n)
		data = pe.get_memory_mapped_image()[ep-(ep_ava - (int(starting_code,16)))+n:ep+ep+0xffffffff]
		offset = 0
		p = open('Assembly.txt','w')
		while offset < len(data):
			i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
			if (pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset) is not None): 
				p.write(str(format((int(starting_code,16))+offset+int(format(n, 'x'),16),'x').zfill(8))+": "+pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)+"\n")
				#out += "\n" +  "one"
				offset += i.length
			else:
				offset += 1
		p.close()
		#////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	return out

def autolabel(ax, rects):
    # attach some text labels
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x()+rect.get_width()/2., 1.05*height, '%d'%int(height),
                ha='center', va='bottom')

def showgraph(opcode_histogram):

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



	autolabel(ax, rects1)

	plt.show()
