import glob,re # lol I'm writing a parser!
import json,os
from build_func_list import lintJSON
PROTO_RE = re.compile(r'\s(BR_PUBLIC_ENTRY|BR_ASM_CALL|__far)')

protos={}

for hfile in glob.glob('brender_sdk/include/*.h'):
	with open(hfile,'r') as f:
		data=f.read()
		data=re.sub(r'(\/\*(?:.*?)\*\/)','',data,flags=re.DOTALL)
		data=re.sub('(\\[\r\n\])',' ',data)

		lines=[x.rstrip('\r\n') for x in data.splitlines()]

	for i,line in enumerate(lines):
		if line.startswith('#'):
			continue
		if PROTO_RE.search(line):
			line=PROTO_RE.sub('',line)
			j=1
			while ';' not in line:
				line+=' '+lines[i+j].lstrip('\t')
				j+=1
			print hfile,line
			line=line.replace(',',', ').strip()
			line=re.sub(r'(\s)(\s+)',r'\1',line)

			name=re.search(r'(\w+)\(',line)
			protos[name.group(1)]={'file':os.path.basename(hfile),'prototype':line,'line':1+i}

with open('prototypes.json','wb') as f:
	f.write(lintJSON(protos))
	
