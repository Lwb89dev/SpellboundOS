#!/usr/bin/env python3
"""NAND partition/driver dispatch and EFTL OOB extraction contracts.

ROM partition rows are original. Driver roots, chip descriptor fields, control
results and page bytes are authored; no hardware access occurs.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH,digest,image_memory
else:
    from recovery_validator import BOOT_HASH,digest,image_memory

ROOT=Path(__file__).resolve().parents[1]
FACTS=ROOT/'analysis/storage-map.json'
PART=0x81300200
SCRATCH=0x81302000
CONFIG=dict(lookup=0x80c29478,partition_lookup=0x80c243d6,ioctl=0x80c2964c,chip_query=0x80c292ee,
    dispatch_ioctl=0x80c27646,read=0x80c29532,dispatch_read=0x80c275ce,
    geometry=0x80c02460,extract=0x80c025d4,oob=0x80c027b0,pack=0x80c026a6,memset=0x80c2e014,
    property=0x80c1d13a,strcmp=0x80c2e3d8,copy=0x80c2de38,logger=0x80c1cd7a,assertion=0x80c16516,
    page_service=0x70000100,fast=0x80c28a98,bad=0x80c29042,mark=0x80c29126,erase=0x80c291e6,range=0x80c28ec4)
RANGES=((0x80c29478,0xba),(0x80c243d6,0x70),(0x80c2964c,0x10e),(0x80c292ee,0x18a),
    (0x80c27646,0x1c),(0x80c29532,0x44),(0x80c275ce,0x20),
    (0x80c02460,0x174),(0x80c025d4,0xd2),(0x80c027b0,0x56),(0x80c026a6,0xe4))
TARGETS=tuple(CONFIG[k] for k in ('lookup','partition_lookup','ioctl','chip_query','dispatch_ioctl','read','dispatch_read','geometry','extract','oob','pack'))
LOGS={0x80c3c0f8:'registry_unready',0x80c3e5d0:'partition_found',0x80c3db08:'chip_error'}


class Stop(Exception):
    def __init__(self,info):self.info=info


class Model:
    def __init__(self,c):
        self.c=c;self.actions=[];self.dims=list(c['seed_dims']);self.buffer=bytearray(b'\xa5'*512)
        if c['mode'] in ('pack','roundtrip'):self.buffer[:4]=bytes(c['pack_data'])
        self.scratch=bytearray((i*5+7)&255 for i in range(8192));self.arg=bytearray(struct.pack('<4I',*c['arguments'])+b'\xa5'*16)
        self.context=bytearray(64)
        if c['mode']!='geometry':
            self.put(0,4,PART);self.context[6]=int(c['fast'])
            self.put(8,4,c['pages_per_block']);self.put(12,4,c['page_size']);self.put(24,4,c['base']//c['page_size'])
            for i,v in enumerate((c['spare'],c['ecc_total'],c['ecc_unit'],*c['positions'])):self.put(28+2*i,2,v)
            self.put(52,4,SCRATCH)
    def put(self,at,n,v):self.context[at:at+n]=(v&((1<<(8*n))-1)).to_bytes(n,'little')
    def get(self,at,n=4):return int.from_bytes(self.context[at:at+n],'little')
    def chip(self,q,arg):
        c=self.c;self.actions.append(f'chip_ioctl:{q}')
        if q==c['inject_query']:
            self.actions.append(f'injected_ioctl_error:{q}');return -9
        if not c['chip_present']:self.actions.append('log:chip_error');return -2
        values={1:c['pages'],2:c['page_size'],3:c['pages_per_block'],13:3,16:1,17:2,
            18:c['spare'],19:c['ecc_total'],20:c['ecc_unit'],25:0x12345678,26:0x90abcdef}
        if q in values:arg[:4]=struct.pack('<I',values[q]);return 0
        if q==21:arg[:16]=struct.pack('<4I',*c['positions']);return 0
        if q in (10,11,12):
            self.actions.append(f'{ {10:"bad",11:"mark",12:"erase"}[q]}:{struct.unpack_from("<I",arg)[0]}:{c["control_status"]}')
            if q==11 and c['control_status']:self.actions.append('log:chip_error')
            return c['control_status']
        if q==15:
            self.actions.append('range:'+':'.join(map(str,struct.unpack_from('<4I',arg)))+':'+str(c['control_status']))
            if c['control_status']:self.actions.append('log:chip_error')
            return c['control_status']
        self.actions.append('log:chip_error');return -9
    def dispatch(self,q,arg,backend='nand'):
        self.actions.append(f'dispatch_ioctl:{backend}:{q}')
        if self.c['driver_state']!='ok':return -6
        return self.chip(q,arg)
    def lookup(self,name):
        c=self.c;rows=json.loads(FACTS.read_bytes())['storage']['partitions'];self.actions.extend(('lookup:'+name,'partition_lookup:'+name))
        row=next((r for r in rows if r['name']==name),None) if c['registry_ready'] else None
        if not c['registry_ready']:self.actions.append('log:registry_unready')
        if row:self.actions.append('log:partition_found');pointer=row['address']
        else:
            self.actions.append('board:nand_partition:'+str(int(c['board_present'])))
            row=next((r for r in rows if r['name']==name),None) if c['board_present'] else None
            if not row:return 0
            pointer=0x80c33678+(row['address']-0x80c33a38)
        for q,slot in ((2,0),(1,1),(3,2)):
            temp=bytearray(struct.pack('<I',self.dims[slot]))
            status=self.dispatch(q,temp,row['backend'])
            self.dims[slot]=struct.unpack('<I',temp)[0]
            if status:return 0
        return pointer
    def extent(self,base,span):
        ps,pages,_=self.dims
        if base&(ps-1):return None
        span=span or ((ps*pages-base)&0xffffffff)
        return None if span&(ps-1) else span
    def ioctl(self,q,arg,base=None,span=None):
        c=self.c;base=c['base'] if base is None else base;span=c['span'] if span is None else span
        if c['null_handle']:return -10
        span=self.extent(base,span)
        if span is None:return -10
        ps,pages,ppb=self.dims;block_size=(ps*ppb)&0xffffffff
        if q==1:
            if c['null_argument']:return -10
            arg[:4]=struct.pack('<I',span//ps);return 0
        if q==8:
            if (base|span)&(block_size-1):return -10
            for block in range(base//block_size,(base+span)//block_size):
                self.dispatch(12,bytearray(struct.pack('<I',block)))
            return 0
        if q in (10,11,12):
            if base&(block_size-1):return -10
            logical=struct.unpack_from('<I',arg)[0]
            return self.dispatch(q,bytearray(struct.pack('<I',(base//block_size+logical)&0xffffffff)))
        if q==15:
            first,second=struct.unpack_from('<II',arg);add=base//ps
            struct.pack_into('<II',arg,0,(first+add)&0xffffffff,(second+add)&0xffffffff)
        return self.dispatch(q,arg)
    def page(self,absolute,column,n,out,target,fast=False):
        c=self.c
        self.actions.append(f'page:{"fast" if fast else "generic"}:{absolute}:{column}:{n}:{c["read_status"]}')
        if c['read_status']>=0:
            count=min(n,c['copy_limit']);target[out:out+count]=bytes((absolute*13+(column+i)*7)&255 for i in range(count))
        return c['read_status']
    def read(self,page,column,n,out,target):
        c=self.c
        if c['null_handle'] or c['null_output']:return -10
        if self.extent(c['base'],c['span']) is None:return -10
        absolute=(page+c['base']//self.dims[0])&0xffffffff
        self.actions.append(f'dispatch_read:nand:{absolute}:{column}:{n}')
        if c['driver_state']!='ok':return -6
        return self.page(absolute,column,n,out,target)
    def extract(self):
        if self.get(30,2)<4:raise Stop(dict(kind='assertion',line=0x48))
        unit=self.get(32,2);positions=[self.get(34+2*i,2) for i in range(4)];ps=self.get(12)
        if unit>=4:
            at=ps+positions[1];self.buffer[:4]=self.scratch[at:at+4];return 0
        done=0
        for i,pos in enumerate(positions):
            count=unit
            if i==0 and pos==0:count=(unit-2)&0xffff;pos=2
            count=min(4-done,count);self.actions.append(f'copy:{done}:{ps+pos}:{count}')
            self.buffer[done:done+count]=self.scratch[ps+pos:ps+pos+count];done+=count
            if done>=4:break
        return 0
    def pack(self):
        ps=self.get(12);spare=self.get(28,2);self.actions.append(f'spare_fill:{ps}:{spare}')
        self.scratch[ps:ps+spare]=b'\xff'*spare
        if self.get(30,2)<4:raise Stop(dict(kind='assertion',line=0x70))
        unit=self.get(32,2);positions=[self.get(34+2*i,2) for i in range(4)]
        if unit>=4:
            at=ps+positions[1];self.scratch[at:at+4]=self.buffer[:4];return 0
        done=0
        for i,pos in enumerate(positions):
            count=unit
            if i==0 and pos==0:count=(unit-2)&0xffff;pos=2
            count=min(4-done,count);self.actions.append(f'pack_copy:{ps+pos}:{done}:{count}')
            self.scratch[ps+pos:ps+pos+count]=self.buffer[done:done+count];done+=count
            if done>=4:break
        return 0
    def geometry(self):
        pointer=self.lookup('eftl');self.put(0,4,pointer)
        if not pointer:raise Stop(dict(kind='assertion',line=0x1a))
        for q,at in ((1,20),(2,12),(3,8)):
            temp=bytearray(4);self.ioctl(q,temp,0x100000,0xb00000);self.context[at:at+4]=temp
        self.put(16,4,self.get(20)//self.get(8));self.put(24,4,0x100000//self.get(12))
        fields=[]
        for q in (18,19,20,21):
            temp=bytearray(16 if q==21 else 4);self.ioctl(q,temp,0x100000,0xb00000)
            fields.extend(struct.unpack('<4I' if q==21 else '<I',temp))
        for i,v in enumerate(fields):self.put(28+2*i,2,v)
        return 0
    def run(self):
        c=self.c;stopped=None
        try:
            mode=c['mode']
            if mode=='lookup':result=self.lookup(c['name_query'])
            elif mode=='ioctl':result=self.ioctl(c['query'],self.arg)
            elif mode=='chip_query':result=self.chip(c['query'],self.arg)
            elif mode=='read':result=self.read(c['page'],c['column'],c['size'],0,self.buffer)
            elif mode=='geometry':result=self.geometry()
            elif mode=='extract':result=self.extract()
            elif mode in ('pack','roundtrip'):
                result=self.pack()
                if mode=='roundtrip':self.buffer[:4]=b'\xa5'*4;result=self.extract()
            elif mode=='oob':
                ps=self.get(12);spare=self.get(28,2)
                if c['fast']:result=self.page((c['page']+self.get(24))&0xffffffff,ps&0xffff,spare,ps,self.scratch,True)
                else:result=self.read(c['page'],ps&0xffff,spare,ps,self.scratch)
                if result==0:result=self.extract()
            else:raise ValueError('NAND probe mode')
            result&=0xffffffff
        except Stop as stop:stopped=stop.info;result=None
        return dict(actions=self.actions,rows=[dict(returned=result,stopped=stopped,dimensions=self.dims,
            argument_hex=self.arg.hex(),buffer_sha256=digest(self.buffer),scratch_sha256=digest(self.scratch),context_hex=self.context.hex())])


def contract(c):
    if not 0<=c['size']<=512 or not 1<=c['page_size']<=4096 or not 0<c['spare']<=128:raise ValueError('bounded NAND probe')
    if any(p+4>c['spare'] for p in c['positions']):raise ValueError('OOB source backing')
    if any(not v for v in c['seed_dims']):raise ValueError('nonzero dispatcher geometry')
    if len(c['pack_data'])!=4 or any(not 0<=v<=255 for v in c['pack_data']):raise ValueError('four OOB bytes')
    return Model(c).run()


def native_vectors():
    cases=[]
    def add(name,mode='ioctl',**changes):
        c=dict(name=name,mode=mode,name_query='eftl',registry_ready=True,board_present=True,driver_state='ok',chip_present=True,
            inject_query=-1,query=2,arguments=[5,9,0x11111111,0x22222222],seed_dims=[2048,32768,64],
            page_size=2048,pages=32768,pages_per_block=64,spare=64,ecc_total=8,ecc_unit=2,positions=[2,8,16,24],
            base=0x100000,span=0xb00000,null_handle=False,null_output=False,null_argument=False,
            control_status=0,read_status=0,copy_limit=512,page=7,column=3,size=32,fast=False,pack_data=[1,0,0x45,0x46])|changes
        c['expected']=contract(c);cases.append(c)
    add('lookup_registry','lookup');add('lookup_board_fallback','lookup',registry_ready=False)
    add('lookup_board_missing','lookup',registry_ready=False,board_present=False)
    add('lookup_missing_name','lookup',name_query='missing')
    add('lookup_chip_absent','lookup',chip_present=False)
    add('lookup_partial_refresh','lookup',page_size=1024,pages=16384,pages_per_block=32,inject_query=1)
    for state in ('root_missing','ops_missing','callback_missing'):add('lookup_'+state,'lookup',driver_state=state)
    add('ioctl_partition_pages',query=1);add('ioctl_derived_pages',query=1,span=0)
    add('ioctl_null_handle',null_handle=True);add('ioctl_null_page_output',query=1,null_argument=True)
    add('ioctl_bad_base',base=0x100001);add('ioctl_bad_span',span=2049)
    add('ioctl_ecc_positions',query=21);add('ioctl_chip_absent',chip_present=False)
    add('ioctl_unknown',query=99);add('ioctl_bad_block_rebase',query=10,control_status=-9)
    add('ioctl_erase_rebase',query=12);add('ioctl_bad_block_alignment',query=10,base=2048)
    add('ioctl_range_rebase',query=15);add('ioctl_range_error',query=15,control_status=-9)
    add('ioctl_range_missing_driver',query=15,driver_state='root_missing')
    add('ioctl_format_ignores_errors',query=8,span=0x40000,control_status=-9)
    add('ioctl_format_bad_alignment',query=8,base=2048)
    add('chip_page_count','chip_query',query=1);add('chip_mark_error','chip_query',query=11,control_status=-9)
    add('read_rebased','read');add('read_error','read',read_status=-9)
    add('read_positive_status','read',read_status=7);add('read_missing_driver','read',driver_state='callback_missing')
    add('read_null_output','read',null_output=True);add('read_derived_span','read',span=0)
    add('read_beyond_span','read',span=2048,page=9999);add('read_zero','read',size=0)
    add('geometry_connected','geometry');add('geometry_fallback','geometry',registry_ready=False)
    add('oob_segmented','oob');add('oob_contiguous','oob',ecc_unit=4)
    add('oob_fast','oob',fast=True);add('oob_error','oob',read_status=-9)
    add('oob_positive_status','oob',read_status=7);add('oob_short_supplied_read','oob',copy_limit=3)
    add('extract_segmented','extract');add('extract_contiguous','extract',ecc_unit=4)
    add('extract_skip_marker','extract',positions=[0,8,16,24])
    add('extract_unit_one_zero_position','extract',ecc_unit=1,positions=[0,8,16,24])
    add('extract_zero_unit','extract',ecc_unit=0)
    add('extract_insufficient_ecc','extract',ecc_total=2)
    add('pack_segmented','pack');add('pack_contiguous','pack',ecc_unit=4)
    add('pack_skip_marker','pack',positions=[0,8,16,24]);add('pack_zero_unit','pack',ecc_unit=0)
    add('pack_insufficient_ecc','pack',ecc_total=2)
    add('roundtrip_segmented','roundtrip');add('roundtrip_contiguous','roundtrip',ecc_unit=4)
    add('roundtrip_marker_skip','roundtrip',positions=[0,8,16,24])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    return dict(boot_sha256=BOOT_HASH,storage_facts_sha256=digest(FACTS.read_bytes()),vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual ROM partition lookup, NAND partition/ioctl/read dispatch, descriptor-backed chip geometry and EFTL geometry/OOB extraction/packing execute.',
            'Driver root, chip descriptor, board-property return, low page/control services and bytes are authored; physical NAND/ECC/bus/erase are not accessed.',
            'Injected query error and malformed extent/ECC cases are bounded fixtures, not measured device faults. OOB assertion stops before its body.',
            'Actual driver registration/probe, electrical geometry/ECC, persistence, SFTL and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND partition: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
