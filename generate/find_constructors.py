import re
from collections import defaultdict

def displayFunction(address):
	show=lastline=False
	fetch=[]
	for line in lines:
		if show:
			if 'RET' in line:
				lastline=True
		else:
			if line.startswith(address):
				show=True
		
		if show:
			fetch.append(line)
			print >>f,'\t',line
			if lastline:
				lastline=show=False
	return '\n'.join(fetch)
def clean(line):
	return line[28:].split(';')[0].strip()
path=r'disassembly.txt'
pattern=re.compile(r'([0-9A-F]+)\s*\/\$.*MOV EAX,ECX\r\n.*OFFSET')



with open(path,'rb') as f:
	data=f.read()
	lines=data.splitlines()

constructors = []
vtables=defaultdict(int)

with open('constructors.txt','w') as f:
	for i,line in enumerate(lines[:-1]):
		cmd=clean(line)
		if cmd=='MOV EAX,ECX':
			nextline=clean(lines[i+1])
			if 'OFFSET' in nextline:
				address = line.split()[0]
				print >>f,'constructor at',address
				func=displayFunction(address)
				for offset in re.findall('OFFSET ([a-fA-F0-9]+)',func):
					vtables[offset]+=1
		
	print >>f,'Found vtables:'
	for t in sorted(list(vtables.items())):
		print >>f,'\t* %s (%d times)' % t
