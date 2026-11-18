#!/usr/bin/env python3
"""Main-image object open/close/write/ioctl and original NAND method contracts."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .main_memory import BASE,MEMBER
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import MAIN_HASH
    from .recovery_validator import digest
else:
    from main_memory import BASE,MEMBER
    from sensorhub_memory import StartupMemory
    from zrpc_packets import MAIN_HASH
    from recovery_validator import digest

OBJECT=0x81327000
TABLE=0x81328000
DATA=0x81329000
OUTPUT=0x8132a000
CB=0x70001000
METHODS=0x70f624c0
PROPERTY=0x70f87acc
OPS=0x70f624dc
CONFIG=dict(open=0x70319470,close=0x703194e0,write=0x70319562,ioctl=0x703195e0,active=0x70319664,
    logger=0x702b38a2,diagnostic=0x703191ac,assertion=0x80d364fa,
    nand_open=0x702d5484,nand_close=0x702d5442,nand_ioctl=0x702d52c6,lower=0x702d5c26)
GENERIC=((CONFIG['open'],112),(CONFIG['close'],130),(CONFIG['write'],126),(CONFIG['ioctl'],132),(CONFIG['active'],14))
NAND=((CONFIG['nand_open'],66),(CONFIG['nand_close'],66),(CONFIG['nand_ioctl'],240))
NAMES=((0x70a441dc,'dev_obj_open'),(0x70a441bc,'dev_obj_close'),(0x70a4419c,'dev_obj_write'),(0x70a4417c,'dev_obj_ioctrl'))
NAND_NAMES=((0x70a30b8c,'dev_nand_open'),(0x70a30bac,'dev_nand_close'),(0x70a30c14,'dev_nand_ioctrl'))
BOUND=10000


def image_memory(archive):
    data=archive.read(MEMBER)
    if digest(data)!=MAIN_HASH:raise ValueError('main image hash')
    return StartupMemory(data,BASE,0x270,4,0x2a0,2)


def names(scope):
    if scope not in ('callbacks','nand'):raise ValueError('main object scope')
    return NAMES+(NAND_NAMES if scope=='nand' else ())


def ranges(scope):names(scope);return GENERIC+(NAND if scope=='nand' else ())
def data_ranges(scope):return tuple((a,len(n)+1) for a,n in names(scope))+(((METHODS,28),(PROPERTY,4),(OPS,28)) if scope=='nand' else ())
def signed(v):return (v&0x7fffffff)-(v&0x80000000)


class Model:
    def __init__(self,c,scope):
        self.c=c;self.scope=scope;self.actions=[];self.rows=[];self.output=bytearray(b'\xa5'*32)
        self.data=bytes((i*3+1)&255 for i in range(64));self.obj=bytearray(b'\xa5'*60)
        self.obj[:32]=b'dev_nand'.ljust(32,b'\0');self.obj[36]=23
        struct.pack_into('<I',self.obj,40,METHODS if scope=='nand' else TABLE if c['table'] else 0)
        self.count(c['count']);struct.pack_into('<II',self.obj,52,0,0x81330000)
        self.stopped=None;self.lower_calls=0
    def refs(self):return struct.unpack_from('<I',self.obj,48)[0]
    def count(self,v):struct.pack_into('<I',self.obj,48,v&0xffffffff)
    def present(self,kind):return kind in ('open','close','ioctl') if self.scope=='nand' else self.c['table'] and self.c['callbacks'][kind]
    def callback(self,kind,op):
        status=0 if self.scope=='nand' else self.c['status'][kind]
        if self.scope=='nand':self.actions.append('nand:'+kind+(f':{op["command"]}' if kind=='ioctl' else ''))
        elif kind=='open':self.actions.append(f'callback:open:{op["flags"]}:{status}')
        elif kind=='close':self.actions.append(f'callback:close:{status}')
        elif kind=='write':self.actions.append(f'callback:write:{op["offset"]}:{op["size"]}:{status}')
        else:
            self.actions.append(f'callback:ioctl:{op["command"]}:{int(op["output"])}:{status}')
            if op['output'] and self.c['callback_output']:struct.pack_into('<I',self.output,0,op['command'])
        return status
    def invalid(self,kind):
        owner,line={'open':(0x70a441dc,297),'close':(0x70a441bc,331),'write':(0x70a4419c,400),'ioctl':(0x70a4417c,491)}[kind]
        self.actions.append('diagnostic:'+kind);self.stopped=dict(kind='assertion',owner=owner,line=line);return None
    def geometry(self,op):
        query=op['command']
        if query==0x1003:return 0
        if query not in (0x1001,0x1002):return -10
        if not op['output']:self.actions.append('log:geometry_null');return -10
        for i,q in enumerate((13,2,1,14),1):
            self.lower_calls+=1;status=self.c['lower_status'] if i==self.c['lower_fail_at'] else 0;value=self.c['geometry'][i-1]
            self.actions.append(f'lower:{q}:{status}:{value}')
            if status:return status
        values=self.c['geometry'];struct.pack_into('<I',self.output,0,values[0]);struct.pack_into('<I',self.output,8,(values[1]*values[2])&0xffffffff);self.output[12]=values[3]&255
        return 0
    def operation(self,op):
        kind=op['op'];self.actions.append('native:'+kind)
        if kind=='active':return int(op['object'] and signed(self.refs())>0)
        if not op['object'] or kind=='write' and not op['data']:return self.invalid(kind)
        n=self.refs()
        if kind=='open':
            if signed(n)>0:self.count(n+1);return 0
            if not self.present(kind):return 0
            status=self.callback(kind,op)
            if not status:self.count(self.refs()+1)
            return status
        if signed(n)<=0:self.actions.append('log:unopened_'+kind);return -14
        if not self.present(kind):return 0
        if kind=='close':
            self.count(n-1)
            return self.callback(kind,op) if self.refs()==0 else 0
        status=self.callback(kind,op)
        return self.geometry(op) if self.scope=='nand' and kind=='ioctl' else status
    def run(self):
        for op in self.c['operations']:
            value=self.operation(op);self.rows.append(dict(returned=None if self.stopped else value&0xffffffff,stopped=self.stopped,
                object_hex=self.obj.hex(),output_hex=self.output.hex(),data_sha256=digest(self.data),lower_calls=self.lower_calls))
            if self.stopped:break
        return dict(actions=self.actions,rows=self.rows)


def contract(c,scope):
    names(scope)
    if not 0<=c['count']<=0xffffffff or not 1<=len(c['operations'])<=12:raise ValueError('object/count bound')
    if set(c['callbacks'])!={'open','close','write','ioctl'} or set(c['status'])!=set(c['callbacks']):raise ValueError('callback fields')
    if any(not -100<=v<=100 for v in c['status'].values()) or not -100<=c['lower_status']<=100 or not 0<=c['lower_fail_at']<=4:raise ValueError('callback status')
    if len(c['geometry'])!=4 or any(not 0<=v<=0xffffffff for v in c['geometry']) or c['geometry'][3]>255:raise ValueError('geometry backing')
    for op in c['operations']:
        if op['op'] not in CONFIG or op['op'] not in ('open','close','write','ioctl','active') or not 0<=op['command']<=65535:raise ValueError('operation')
        if not 0<=op['flags']<=0xffffffff or not 0<=op['size']<=64 or not 0<=op['offset']<=0xffffffff:raise ValueError('arguments')
    return Model(c,scope).run()


def native_vectors(scope='callbacks'):
    names(scope);cases=[]
    def op(kind,**kw):return dict(op=kind,object=True,data=True,output=True,command=0x1001,flags=0x1234,offset=5,size=8)|kw
    def add(name,ops,count=0,**changes):
        c=dict(name=name,count=count,table=True,callbacks={k:True for k in ('open','close','write','ioctl')},status=dict(open=0,close=0,write=8,ioctl=0),
            callback_output=True,lower_fail_at=0,lower_status=-9,geometry=[0xbaef,2048,65536,1],operations=ops)|changes
        c['expected']=contract(c,scope);cases.append(c)
    if scope=='callbacks':
        add('main_open_close',[op('open'),op('active'),op('close'),op('active'),op('ioctl')])
        add('main_two_refs',[op('open'),op('open'),op('close'),op('active'),op('close'),op('active')])
        add('main_close_error',[op('close'),op('active'),op('close'),op('ioctl')],count=1,status=dict(open=0,close=-9,write=8,ioctl=0))
        add('main_reopen_after_close_error',[op('close'),op('open'),op('active')],count=1,status=dict(open=0,close=-9,write=8,ioctl=0))
        add('main_missing_close',[op('close'),op('active')],count=1,callbacks=dict(open=True,close=False,write=True,ioctl=True))
        add('main_no_table',[op('close'),op('active')],count=1,table=False)
        add('main_close_zero',[op('close'),op('active')]);add('main_close_negative',[op('close'),op('active')],count=0xffffffff)
        add('main_open_missing',[op('open'),op('active')],callbacks=dict(open=False,close=True,write=True,ioctl=True))
        add('main_open_error',[op('open'),op('active')],status=dict(open=-9,close=0,write=8,ioctl=0))
        add('main_open_negative',[op('open'),op('active')],count=0xffffffff)
        add('main_open_overflow',[op('open'),op('active'),op('close')],count=0x7fffffff)
        add('main_write',[op('write')],count=1);add('main_write_error',[op('write')],count=1,status=dict(open=0,close=0,write=-9,ioctl=0))
        add('main_write_closed',[op('write')]);add('main_write_missing',[op('write')],count=1,callbacks=dict(open=True,close=True,write=False,ioctl=True))
        add('main_ioctl',[op('ioctl')],count=1);add('main_ioctl_error',[op('ioctl')],count=1,status=dict(open=0,close=0,write=8,ioctl=-9))
        add('main_ioctl_closed',[op('ioctl')]);add('main_ioctl_missing',[op('ioctl')],count=1,callbacks=dict(open=True,close=True,write=True,ioctl=False))
        for kind in ('open','close','write','ioctl','active'):add('main_null_'+kind,[op(kind,object=False)],count=1)
        add('main_null_write_data',[op('write',data=False)],count=1)
    else:
        add('nand_main_cycle',[op('open'),op('ioctl'),op('close'),op('active'),op('ioctl')])
        add('nand_main_two_refs',[op('open'),op('open'),op('close'),op('ioctl'),op('close'),op('active')])
        add('nand_main_reopen',[op('open'),op('close'),op('open'),op('ioctl')])
        add('nand_main_closed',[op('ioctl')]);add('nand_main_write_slot',[op('open'),op('write'),op('close')])
        add('nand_main_no_bbt',[op('open'),op('ioctl')],geometry=[0xbaef,2048,65536,0])
        add('nand_main_alias',[op('open'),op('ioctl',command=0x1002)])
        add('nand_main_noop',[op('open'),op('ioctl',command=0x1003,output=False)])
        add('nand_main_invalid',[op('open'),op('ioctl',command=0x1000)])
        add('nand_main_null_output',[op('open'),op('ioctl',output=False)])
        for i in range(1,5):add('nand_main_query_error_'+str(i),[op('open'),op('ioctl'),op('close')],lower_fail_at=i)
        add('nand_main_wrapping_capacity',[op('open'),op('ioctl')],geometry=[0xbaef,0x10000,0x10000,1])
    return dict(schema=1,scope=scope,bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());memory=image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    for a,name in names(scope):
        if memory.read(a,len(name)+1)!=name.encode()+b'\0':raise ValueError('original owner name')
    return dict(scope=scope,main_sha256=MAIN_HASH,function_names={f'{a:08x}':n for a,n in names(scope)},
        vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in ranges(scope)},
        data_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in data_ranges(scope)},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges(scope)},native_validation=report,
        native_steps=sum(row['steps'] for row in report['cases']),limitations=[
            'Main-image generic open/close/write/ioctl/active bodies execute on an authored object, counters and buffers; callbacks scope supplies method results/effects.',
            'NAND scope uses original method/property/operation tables and actual main NAND open/close/ioctl methods, with lower driver geometry queries supplied; main probe/registration/media and RTOS are not executed.',
            'Close/reference state does not establish removal, deallocation, physical hardware shutdown or concurrent ownership; initial negative/wrapping values are authored counterexamples.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('callbacks','nand'),default='callbacks')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main object lifecycle: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
