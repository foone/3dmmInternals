import struct,sys,json,glob,os
from build_func_list import lintJSON

def decodeNames(rest):
	i=0
	while i<len(rest)-1:
		length=ord(rest[i])
		yield rest[i+1:i+1+length]
		i+=length+1

def decodePubdef(rest,bit32):
	i=2
	while i<len(rest)-1:
		length=ord(rest[i])
		yield rest[i+1:i+1+length]
		i+=length+4+(2 if bit32 else 0)


def handleLibraryFileFormat(length):
	global page_size
	page_size=length


def getMore(type,length,offset):
	global current_file
	rest=data[offset:offset+length-3]
	if type==0x80: # start object file
		fname=decodeNames(rest).next().lower()
		current_file = fname
	elif type in (0x90,0x91): # start function
		pubs=tuple(decodePubdef(rest,type==0x91))
		for func in pubs:
			library[func]={'lib_filename':os.path.basename(library_filename),'object_file':current_file}
	elif type==0xF0:
		handleLibraryFileFormat(length)
	elif type in (0x8A,0x8B): # end object file 
		current_file = None
	

library={}

for library_filename in glob.glob(os.path.join('brender_sdk','lib','fixed','*.lib')):
	with open(library_filename,'rb') as f:
		data=f.read()

	offset=0
	page_size=0
	current_file=None
	
	while True:
		type,length=struct.unpack('<BH',data[offset:offset+3])
		length+=3
		getMore(type,length,offset+3)
		offset=offset+length
		if type in (0x8A,0x8B):
			M=offset%page_size
			if M>0:
				M=page_size-M
			offset+=M
		elif type==0xF1:
			break




with open('brender_libs.json','wb') as f:
	f.write(lintJSON(library))
	