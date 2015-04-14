# -*- coding: utf-8 -*- 

import os, sys, subprocess, signal, base64, array, binascii, random, re, math
from subprocess import Popen, PIPE
import pyxed, pydasm, pefile, inspect

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
		if(m.start()<2048):
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

	#/////////////////////////////////////////////////////////////////////Run Instructions Byte by Byte to create a Answer Key
	q = 0 # tracks header pointer
	p = 2 # tracks tail pointer
	# hex string to track for testing

	#SET HEXDIG to file input
	#hexdig = binhex

	instr_key = dict()
				
	if m is not None:
		#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		pe =  pefile.PE(filename)
		ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		starting_code = str(int(code_base) + int(image_base))
		ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
		data = pe.get_memory_mapped_image()[ep-(ep_ava - (int(starting_code,16))):ep+0xffffffff]
		p = open('instructions_pyd.txt','w+')
		p.write(binascii.hexlify(data))
		p.close()
		offset = 0
		p = open('Assembly_pefile.txt','w')
		while offset < len(data):
			i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
			if (pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset) is not None): 
				p.write(str(format((int(starting_code,16))+offset,'x' ).zfill(8))+": "+pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)+"\n")
				instr_key[str(format((int(starting_code,16))+offset,'x' ).zfill(8))] = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
				#out += "\n" +  "one"
				offset += i.length
			else:
				offset += 1
		p.close()
		
		total = 0
		#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		# LIST OF IMPORTED FILE AND FUNCTIONS
		p = open("Imported.txt", 'w')
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			p.write( "DLL: "+entry.dll+"\n")
			for imp in entry.imports:
				#total += imp.hint
				#print hex(((imp.address-int(image_base,16)))*2)
				p.write( '\tAddr: ' + hex(imp.address) +  ", Name:"+ imp.name +" hint: " + str(imp.hint)  + "\n")
				#data = binhex[(imp.address-int(image_base,16))*2:(imp.address-int(image_base,16) + imp.hint)*2]
				#p.write(data)
				#print hex(imp.address-int(image_base,16)) +" : "+ str(len(data))+ " : " + hex(imp.address+imp.hint-int(image_base,16)) 
				#offset = 0
				#while offset < len(data):
				#	i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
				#	if (pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset) is not None): 
				#		p.write("\t\t"+str(format((int(starting_code,16))+offset,'x' ).zfill(8))+": "+pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)+"\n")
				#		#out += "\n" +  "one"
				#		offset += i.length
				#	else:
				#		offset += 1
		#print "Total: " + str(total) + hex(len(binhex))
		p.close()
		#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		pe =  pefile.PE(filename)
		ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		starting_code = str(int(code_base) + int(image_base))
		ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
		data = pe.get_memory_mapped_image()[ep-(ep_ava - (int(starting_code,16))):ep+0xffffffff]
		offset = 0
		p = open('Assembly.txt','w')
		while offset < len(data):
			i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
			if (pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset) is not None): 
				p.write(str(format((int(starting_code,16))+offset,'x' ).zfill(8))+": "+pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)+"\n")
				#out += "\n" +  "one"
				offset += i.length
			else:
				offset += 1
		p.close()
		
		'''		random start info
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
		#p = open('temp.txt','w')
		while offset < len(data):
			i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
			if (pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset) is not None): 
				p.write(str(format((int(starting_code,16))+offset+int(format(n, 'x'),16),'x').zfill(8))+": "+pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)+"\n")
				#out += "\n" +  "one"
				offset += i.length
			else:
				offset += 1
		p.close()
		'''
		#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	p = open("CFG.txt",'w')
	for x in sorted(instr_key):
		p.write(x +":"+ instr_key[x]+"\n")
	p.close()
	 
	# print sections and sizes
	for section in pe.sections:
		 print (section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData )
	#/////////////////////////////////////////////////////////////////////////////////////////////////////
	
	# full dump info
	p = open("Full.txt", 'w')		
	p.write( pe.dump_info())	
	p.close()
	#/////////////////////////////////////////////////////////////////////////////////////////////////////
	
	
	
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
