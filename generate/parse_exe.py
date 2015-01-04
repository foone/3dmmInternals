import pefile,ms3dmm,os,pdb,struct,json
from bitfield import *
FPOFlags=make_bf('FPOFlags',[
	('prolog',c_uint,8),
	('regs',c_uint,3),
	('SEH',c_bool,1),
	('BP',c_bool,1),
	('reserved',c_bool,1),
	('frame',c_uint,2),
], basetype=c_uint16)
path='3dmovie.exe'
if not os.path.exists(path):
	path=ms3dmm.getEXEPath()

pe =  pefile.PE(path)

base = pe.OPTIONAL_HEADER.ImageBase

functions={}

for section in pe.DIRECTORY_ENTRY_DEBUG:
	if section.struct.Type==pefile.DEBUG_TYPE['IMAGE_DEBUG_TYPE_FPO']:
		data=pe.get_data(section.struct.PointerToRawData,section.struct.SizeOfData)
		for offset in range(0,len(data),16):
			start,size,locals,params,flag_data=struct.unpack('<LLLHH',data[offset:offset+16])
			flags=FPOFlags()
			flags.base=flag_data
			
			func={'size':size,'locals':locals*4,'params':params*4,}
			for k,v in flags.items():
				if k in ('reserved',):
					continue
				func[k]=v
			
			functions['%08x' % (base+start)]=func
			
with open('fpo.json','wb') as f:
	json.dump(functions,f)
			
			
