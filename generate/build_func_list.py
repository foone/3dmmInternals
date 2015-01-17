import json,collections,subprocess,os
JSONLINT_PATH = os.path.expanduser(r'~\Application Data\npm\jsonlint.cmd')

functions=collections.defaultdict(dict)

def lintJSON(jobj):
	p=subprocess.Popen([JSONLINT_PATH,'-'], 
		stdout=subprocess.PIPE, stdin=subprocess.PIPE
	)
	out,_=p.communicate(json.dumps(jobj,sort_keys=True))
	return out

def cleanAddress(x):
	return x.upper().rjust(8,'0')

if __name__=='__main__':

	with open('disassembly.txt','r') as f:
		f.next();f.next()
		for line in f:
			line=line.rstrip()
			if line[10:12] in ('/.','/$'):
				address=line[:10].strip()
				function={}
				parts=line.split(';',1)
				rest=line[12:]
				if len(parts)>1:
					name=parts[1].strip().replace('quickstart.','3DMOVIE.')
					if not name.startswith('3DMOVIE.'):
						continue
					args=None
					if '(' in name:
						parts=name.split('(',1)
						name=parts[0]
						args=parts[1].rstrip(')').strip()
						if args.startswith('guessed '):
							args=args[8:]
						function['args']=args
					function['name']=name
				else:
					function['name']='unnamed'
				functions[cleanAddress(address)]['ollydbg']=function

	with open('constructors.txt','r') as f:
		address=None
		for line in f:
			if line.startswith('constructor at'):
				address=line[15:].strip()
				functions[address]['constructor']={'vtables':[]}
			if 'MOV DWORD PTR DS:[ECX' in line and 'OFFSET' in line:
				i=line.index('OFFSET')
				vtables=functions[cleanAddress(address)]['constructor']['vtables']
				vtables.append(line[i+7:].strip())
				vtables.sort()

	with open('ida.txt','r') as f:
		for line in f:
			address=line[159:168].strip()
			function={'name':line[:153].strip(),'length':int(line[168:176].strip().lstrip('0'),16)}
			
			flags=line[176:]
			FLAGS={'R':'returns','L':'library','S':'static','B':'bp-based-frame','T':'type-info'}
			for flag,outputname in FLAGS.items():
				function[outputname]=flag in flags
			
			functions[cleanAddress(address)]['ida']=function
			
	with open('fpo.json','rb') as f:
		fpo=json.load(f)
		for address in fpo:
			functions[cleanAddress(address)]['fpo']=fpo[address]
				
	with open('../functions.json','wb') as jf:
		jf.write(lintJSON({'functions':functions}))