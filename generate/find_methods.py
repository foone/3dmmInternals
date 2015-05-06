import re,collections,itertools,json
import os,pdb
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

class Function(object):
	def __init__(self,lines=None):
		if lines is None:
			lines=[]
		self.lines=lines
	
	def add(self,line):
		if line.isSpacer():
			return # ignore this line rather than adding it to the function
		self.lines.append(line)
	

	def analyzeMethod(self):
		any_ecx=any('ECX' in line.command for line in self.lines)
		any_args=any('[ARG.' in line.command for line in self.lines)

		if any_args:
			certain_or_fastcall='definitely'
		else:
			certain_or_fastcall='could-be-fastcall'


		if any_ecx:
			for line in self.lines:
				#print '*  ',line.command
				if 'ECX' in line.command:
					args=line.arguments
					if 'ECX' in args[0]:
						if '[' in args[0]:
							if 'OFFSET 00' in line.command:
								return 'constructor'
							return certain_or_fastcall
						else:
							if line.operator=='ADD':
								return 'casted'
							if line.operator in ('PUSH','POP'):
								continue
							if line.operator=='MOV' and args[0]=='ECX':
								return 'could-be-this-assignment'
							else:
								return 'ecx-overwritten'
						return 
					else:
						return certain_or_fastcall
			return 'maybe'
		else:
			return 'no-ecx'

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
		self.command=self.command.strip().lstrip('/|\\')

	def __str__(self):
		return 'Disassembly({})'.format(', '.join('{}={}'.format(key,getattr(self,key)) for key in Disassembly.PARTS))

	def isSpacer(self):
		return self.command=='INT3'
	
	def startsNewFunction(self):
		return self.indicator=='/$'

	@property
	def operator(self):
		return self.command.split(' ',1)[0]

	@property
	def arguments(self):
		return self.command.split(' ',1)[1].split(',')

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
	method_analysis={}
	for function in Function.parse('disassembly.txt'):
		#print function,len(function)
		method_analysis[function.address]=function.analyzeMethod()
	
	with open('method-analysis.json','wb') as f:
		f.write(lintJSON(method_analysis))
		
