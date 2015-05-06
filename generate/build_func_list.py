import sys
sys.path.append('lib')
import json,collections,subprocess,os,glob
if 'linux' in sys.platform:
	JSONLINT_PATH = 'jsonlint'
else:
	JSONLINT_PATH = os.path.expanduser(r'~\Application Data\npm\jsonlint.cmd')

functions=collections.defaultdict(dict)

def lintJSON(jobj):
	unlinted=json.dumps(jobj,sort_keys=True)
	try:
		p=subprocess.Popen([JSONLINT_PATH,'-'], 
			stdout=subprocess.PIPE, stdin=subprocess.PIPE
		)
		return p.communicate(unlinted)[0]
	except OSError:
		print >>sys.stderr,'Warning: Failed to pretty-print json!'
		return unlinted

def cleanAddress(x):
	return x.upper().rjust(8,'0')

def dealiasFunction(x):
	return x.strip().lstrip('_').lower()

if __name__=='__main__':
	import pefile,ms3dmm,pyudd

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

	pe =  pefile.PE(ms3dmm.getAnyEXE())
	base = pe.OPTIONAL_HEADER.ImageBase

	for uddfile in glob.glob('*.udd'):
		u = pyudd.Udd(filename=uddfile)
		for i in u.find_by_type("\nDat"):
			data=pyudd.expand_chunk(u.get_chunk(i),u.get_format())
			if data['category']==pyudd.OLLY2CATS['UserLabel']:
				address='%08X' % (base+data['RVA'])
				functions[address]['manual-ollydbg']={'name':data['name']}
		
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
	
	for keyname in ('fpo','method-analysis'):
		with open('{}.json'.format(keyname),'rb') as f:
			for address,data in json.load(f).items():
				functions[cleanAddress(address)][keyname]=data

	with open('prototypes.json','rb') as f:
		prototypes={}
		for name,function_prototype in json.load(f).items():
			prototypes[dealiasFunction(name)]=function_prototype

		library_info={}
		with open('brender_libs.json','rb') as blf:
			for name,function_info in json.load(blf).items():
				library_info[dealiasFunction(name)]=function_info

		for address,func in functions.items():
			names=[dealiasFunction(func[key]['name']) for key in func if 'name' in func[key]]
			for name in names:
				proto = prototypes.get(name)
				if proto:
					func['prototype']=proto
				info = library_info.get(name)
				if info:
					func['library']=info

	with open('../functions.json','wb') as jf:
		jf.write(lintJSON({'functions':functions}))