import re,collections,itertools,json
import pefile,ms3dmm,os,pdb,struct
from build_func_list import lintJSON


def parseFixed(line,*segments):
	i=0
	for segment in segments:
		if segment<0:
			segment=-segment
		elif segment>0:
			yield line[i:i+segment]
		else: # ==0
			yield line[i:]
			return
		i+=segment

class EXE(object):
	def __init__(self):
		pe=self.pe = pefile.PE(ms3dmm.getAnyEXE())
		self.base=pe.OPTIONAL_HEADER.ImageBase
		self.data=pe.get_memory_mapped_image()

	def probeVTable(self, address):
		data,base=self.data,self.base
		def probeForPiece():
			for i in itertools.count():
				o=address-base+(4*i)
				yield struct.unpack('<L',data[o:o+4])[0]
		return itertools.takewhile(lambda x:x!=0, probeForPiece())


class Source(object):

	def __init__(self):
		self.json_file = '../classes.json'

		self.constructors={}
		self.vtables=collections.defaultdict(list)
		self.vtable_entries=collections.defaultdict(list)
		self.class_ids={}
		self.malloc_calls={}
		self.classes=collections.defaultdict(lambda:collections.defaultdict(dict))
		self.loadJSON()

		

	def parse(self, filename):
		for function in Function.parse('disassembly.txt'):
			if function.isConstructor():
				self.constructors[function.address]=function
				for offset,line in function.getVTableLines():
					self.vtables[function.address].append((line,offset))
				self.malloc_calls[function.address]=list(function.findMallocCalls())
			classid,line=function.getClassID()
			if classid:
				self.class_ids[function.address]=(line,classid)

	def parseVTables(self, exe):
		for function_address,lines in self.vtables.items():
			for line,offset in lines:
				address=int(offset,16)
				self.vtable_entries[(function_address,offset)].extend(exe.probeVTable(address))

	def findConstructorsForClassIDs(self):
		for (function_address,offset),entries in self.vtable_entries.items():
			klass = self.addClass(function_address, offset)
			mallocs=self.malloc_calls.get(function_address,[])
			if mallocs:
				klass['malloc-sizes']=mallocs
			klass['vtable']=entries


			if len(entries)<5:
				print 'TOO SMALL FOR BASETHING',function_address,offset
				continue # BaseThing has 5 virtual methods, so if there are less than 5 this isn't a BaseThing subclass
			id_method='%08X' % entries[1]
			line,classid = self.class_ids.get(id_method,(None,None))
			if line:
				cid=int(classid,16)
				cidstr=Source.cleanClassID(cid)
				print 'POSSIBLE CLASS ID',function_address,offset,cidstr,len(entries),mallocs
				klass['id']={'hex':classid,'string':cidstr}
			else:
				print 'VTABLE, NO CLASSID',function_address,offset,id_method,len(entries),mallocs
			

	def addClass(self,address,offset):
		klass = self.classes[address]['find_classes'][offset]={}
		return klass


	def loadJSON(self):
		try:
			with open(self.json_file,'rb') as f:
				self.classes.update(json.load(f))
		except IOError:
			pass

	def saveJSON(self):
		with open(self.json_file,'wb') as f:
			f.write(lintJSON({'classes':self.classes}))

	@staticmethod
	def cleanClassID(classid):
		s=struct.pack('!L',classid)
		return re.sub('[^A-Za-z0-9 ]','?',s.replace('\0',' '))

class Function(object):
	CLASS_ID_PATTERN      = re.compile(r"^MOV EAX,(?:OFFSET )?([0-9A-F]{3,})$")
	VTABLE_LOAD_PATTERN   = re.compile(r"^MOV DWORD PTR DS:\[[A-Z]{3}\],OFFSET ([0-9A-F]+)")
	PUSH_CONSTANT_PATTERN = re.compile(r"^PUSH ([0-9A-F]+)$")

	def __init__(self,lines=None):
		if lines is None:
			lines=[]
		self.lines=lines
	
	def add(self,line):
		if line.isSpacer():
			return # ignore this line rather than adding it to the function
		self.lines.append(line)
	
	def getClassID(self):
		lines=self.lines
		if len(lines)==2 and lines[1].command=='RETN':
			m=Function.CLASS_ID_PATTERN.match(lines[0].command)
			if m:
				return m.group(1),lines[0]
		return None,None

	def isConstructor(self):
		return any(Function.VTABLE_LOAD_PATTERN.match(line.command) for line in self.lines)

	def getVTableLines(self):
		for line in self.lines:
			m=Function.VTABLE_LOAD_PATTERN.search(line.command)
			if m:
				yield m.group(1),line

	def findMallocCalls(self):
		prev=None
		for line in self.lines:
			if line.command=='CALL malloc':
				if prev:
					m=Function.PUSH_CONSTANT_PATTERN.search(prev.command)
					if m:
						yield int(m.group(1),16)
			prev=line

	@property
	def address(self):
		try:
			return self.lines[0].address
		except IndexError:
			return None

	def length(self):
		return len(self.lines)

	def __len__(self):
		return len(self.lines)

	def __iter__(self):
		return self.lines.__iter__()

	def __repr__(self):
		lines=self.lines
		if not lines:
			return 'Function<Empty>'
		else:
			return 'Function<%08X>' % self.lines[0].addressValue

	@staticmethod
	def parse(filename):
		buffer=Function()
		for line in Disassembly.parse(filename):
			if line.isSpacer() or line.startsNewFunction():
				if buffer:
					yield buffer
					buffer=Function()
			buffer.add(line)
		if buffer:
			yield buffer

class Disassembly(object):
	ADDRESS_PATTERN = re.compile('^[0-9A-F]{8}  ')
	
	PARTS=('address','indicator','hex','command','comments')
	def __init__(self,buffer):
		self.line = line = '\n'.join(buffer)
		self.address,self.indicator,self.hex,self.command,comments=parseFixed(line,8,-2,2,-2,13,-1,41,0)
		if comments.startswith(';'):
			self.comments=comments[1:]
		else:
			self.comments=''
		self.command=self.command.strip()

	def __str__(self):
		return 'Disassembly({})'.format(', '.join('{}={}'.format(key,getattr(self,key)) for key in Disassembly.PARTS))

	def isSpacer(self):
		return self.command=='INT3'
	
	def startsNewFunction(self):
		return self.indicator=='/$'

	@property
	def addressValue(self):
		return int(self.address,16)

	@staticmethod
	def parse(file):
		with open(file,'rb') as f:
			f.next() # skip header
			f.next()
			buffer=[]
			for line in f:
				if Disassembly.ADDRESS_PATTERN.match(line):
					if buffer:
						yield Disassembly(buffer)
					buffer=[]
				buffer.append(line.rstrip('\r\n'))
			if buffer:
				yield Disassembly(buffer)

if __name__=='__main__':
	source = Source()
	source.parse('disassembly.txt')
	exe=EXE()
	source.parseVTables(exe)
	source.findConstructorsForClassIDs()
	source.saveJSON()
	"""
	for function in Function.parse('disassembly.txt'):
		if function.isConstructor():
			print function,len(function),function.isClassID(),function.isConstructor()
			for line in function:
				print '\t%s' % line.line
				pass
		c=c+1
	print c
	"""