#!/usr/bin/env python3
"""Original object open/reference policy and connected NAND object consumers."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_object_stack as objects
else:
    import nand_object_stack as objects

probe=objects.probe
qspi=objects.qspi
TABLE=0x81325000
OUTPUT=0x81326000
OPEN_CALLBACK=0x70001000
IOCTL_CALLBACK=0x70001004
GENERIC=((0x80c2cfe0,110),(0x80c2d04e,108),(0x80c2d0ba,128))
NAND_METHODS=((0x80c274e6,62),(0x80c27338,236),(0x80c27466,66),(0x80c27424,66))
NAND_CONTEXT=((0x80c27b64,64),(0x80c27a90,28),(0x80c27af2,58),(0x80c27b2c,56))
GENERIC_NAMES=((0x80c3f5d4,'dev_obj_ioctrl'),(0x80c3f5f4,'dev_obj_open'))
NAND_NAMES=((0x80c3d160,'dev_nand_open'),(0x80c3d1a0,'dev_nand_suspend'),
            (0x80c3d1c8,'dev_nand_resume'),(0x80c3d1e8,'dev_nand_ioctrl'))


def ranges(scope):
    if scope=='open':return objects.ranges('registry')+GENERIC
    if scope=='consumer':return tuple(dict.fromkeys(objects.ranges('root')+GENERIC+NAND_METHODS+NAND_CONTEXT))
    raise ValueError('object lifetime scope')


def data_ranges(scope):
    ranges(scope);base=objects.data_ranges('root' if scope=='consumer' else 'registry')
    return tuple(dict.fromkeys(base+tuple((a,len(name)+1) for a,name in function_names(scope))))


def function_names(scope):
    ranges(scope);return GENERIC_NAMES+(NAND_NAMES if scope=='consumer' else ())


def signed(value):return (value&0x7fffffff)-(value&0x80000000)


class LifeMixin:
    def init_lifetime(self):
        self.life_output=bytearray(b'\xa5'*32);self.life_calls=[];self.life_root_return=None
        for i,b in enumerate(self.nodes):
            struct.pack_into('<I',b,40,0 if self.c['life_tables'][i]=='none' else TABLE+32*i)
            struct.pack_into('<I',b,48,self.c['life_counts'][i])
    def reference_count(self,slot):return struct.unpack_from('<I',self.nodes[slot],48)[0]
    def put_count(self,slot,value):struct.pack_into('<I',self.nodes[slot],48,value&0xffffffff)
    def fail_null(self,owner,line,kind):
        self.actions.append('life_invalid:'+kind);self.stopped=dict(kind='assertion',owner=owner,line=line);return None
    def callback_open(self,slot,flags):
        if self.c['native_nand_root']:
            self.actions.append(f'life_nand_open:{slot}:{flags}');return 0
        self.actions.append(f'life_callback_open:{slot}:{flags}:{self.c["life_open_status"]}');return self.c['life_open_status']
    def method_present(self,slot,kind):
        if self.c['native_nand_root'] and slot==3:return True
        mode=self.c['life_tables'][slot];return mode!='none' and mode!=f'no_{kind}'
    def open_object(self,slot,flags):
        self.actions.append(f'life_open_native:{slot}:{flags}')
        if slot<0:return self.fail_null(0x80c3f5f4,297,'open')
        count=self.reference_count(slot)
        if signed(count)>0:self.put_count(slot,count+1);return 0
        if not self.method_present(slot,'open'):return 0
        status=self.callback_open(slot,flags)
        if not status:self.put_count(slot,self.reference_count(slot)+1)
        return status
    def register_open(self,op):
        slot=op['slot'];flags=op['flags'];self.actions.append(f'life_register_open_native:{slot}:{flags}')
        status=self.object_register(slot,op['name'],op['type'])
        if self.stopped:return None
        if status:return -1
        count=self.reference_count(slot)
        if signed(count)<=0:
            if not self.method_present(slot,'open'):return 0
            status=self.callback_open(slot,flags)
            if status:self.actions.append('log:object_open_failed');return status
        self.put_count(slot,self.reference_count(slot)+1);return 0
    def nand_query(self,query):
        self.actions.append(f'life_driver_ioctl:{query}');c=self.c
        self.actions.append('life_irq:'+str(c['life_irq']))
        direct=bool(c['life_irq'])
        if not direct:self.actions.append('life_scheduler:'+str(c['life_scheduler']));direct=bool(c['life_scheduler'])
        if not direct and self.mutex:
            status=c['life_acquire'];self.actions.append(f'life_nand_acquire:{status}')
            if status:self.stopped=dict(kind='assertion',owner=0x80c3d464,line=36);return None,None
        self.actions.append(f'life_chip_ioctl:{query}')
        chip=probe.CHIPS[0];values={13:chip['id'][0]|chip['id'][1]<<8,2:chip['page_size'],1:chip['pages'],14:int(self.bword(0)==objects.aux.joined.recovery.bbt.MAGIC)}
        value=values[query]
        if not direct and self.mutex:
            status=c['life_release'];self.actions.append(f'life_nand_release:{status}')
            if status:self.stopped=dict(kind='assertion',owner=0x80c3d44c,line=42);return None,None
        return 0,value
    def ioctl_object(self,op):
        slot=op['slot'];query=op['query'];self.actions.append(f'life_ioctl_native:{slot}:{query}')
        if slot<0:return self.fail_null(0x80c3f5d4,491,'ioctl')
        if signed(self.reference_count(slot))<=0:self.actions.append('log:object_not_open');return -14
        if not self.method_present(slot,'ioctl'):return 0
        if not self.c['native_nand_root']:
            self.actions.append(f'life_callback_ioctl:{slot}:{query}:{int(op["null_output"])}:{self.c["life_ioctl_status"]}')
            if self.c['life_callback_write'] and not op['null_output']:struct.pack_into('<I',self.life_output,0,query)
            return self.c['life_ioctl_status']
        self.actions.append(f'life_nand_ioctl:{slot}:{query}')
        if query==0x1003:return 0
        if query not in (0x1001,0x1002):return -10
        if op['null_output']:self.actions.append('log:object_geometry_null');return -10
        values=[]
        for code in (13,2,1,14):
            status,value=self.nand_query(code)
            if self.stopped:return None
            if status:return status
            values.append(value)
        struct.pack_into('<I',self.life_output,0,values[0]);struct.pack_into('<I',self.life_output,8,values[1]*values[2]);self.life_output[12]=values[3]
        return 0
    def run_life(self):
        value=0
        for op in self.c['life_ops']:
            if op['kind']=='open':value=self.open_object(op['slot'],op['flags'])
            elif op['kind']=='register_open':value=self.register_open(op)
            elif op['kind']=='ioctl':value=self.ioctl_object(op)
            else:
                self.actions.append(f'life_nand_{op["kind"]}:{op["slot"]}');value=0
            self.life_calls.append(dict(kind=op['kind'],returned=None if self.stopped else value&0xffffffff,
                counts=[self.reference_count(i) for i in range(4)],output_hex=self.life_output.hex()))
            if self.stopped:break
        return value
    def finish_life(self,result):
        result['rows'][0].update(lifetime_calls=self.life_calls,lifetime_root_return=self.life_root_return,lifetime_output_hex=self.life_output.hex())
        return result


class OpenModel(LifeMixin,objects.RegistryModel):
    def __init__(self,c):super().__init__(c);self.init_lifetime()
    def run_probe_entry(self):return self.run_life()
    def run(self):return self.finish_life(super().run())


class ConsumerModel(LifeMixin,objects.RootModel):
    def __init__(self,c):super().__init__(c);self.init_lifetime()
    def root_followups(self,value):
        if not self.stopped:
            self.life_root_return=value&0xffffffff
            if not value:self.run_life()
        return value
    def run(self):return self.finish_life(super().run())


def contract(c,scope):
    ranges(scope)
    if not c['native_object_lifetime'] or c['native_nand_root']!=(scope=='consumer'):raise ValueError('lifetime entry')
    if len(c['life_tables'])!=4 or any(v not in ('all','none','no_open','no_ioctl') for v in c['life_tables']):raise ValueError('method tables')
    if len(c['life_counts'])!=4 or any(not 0<=v<=0xffffffff for v in c['life_counts']):raise ValueError('reference backing')
    if not 1<=len(c['life_ops'])<=8 or c['registry_ops']:raise ValueError('lifetime operations')
    for op in c['life_ops']:
        if op['kind'] not in ('open','register_open','ioctl','suspend','resume') or not -1<=op['slot']<=3:raise ValueError('lifetime operation')
        if not 0<=op['flags']<=0xffffffff or not 0<=op['query']<=65535:raise ValueError('lifetime arguments')
        if scope=='open' and op['kind'] in ('suspend','resume'):raise ValueError('NAND method scope')
        if scope=='consumer' and (op['slot']!=3 or op['kind']=='register_open'):raise ValueError('published NAND consumer')
        if op['kind']=='register_open':
            if not isinstance(op['name'],str) or not op['name'].isascii() or '\0' in op['name'] or len(op['name'])>64 or not 0<=op['type']<=65535:raise ValueError('register-open input')
    if any(not -100<=c[k]<=100 for k in ('life_open_status','life_ioctl_status','life_acquire','life_release')) or any(c[k] not in (0,1) for k in ('life_irq','life_scheduler')):raise ValueError('lifetime services')
    baseline=c|dict(native_object_lifetime=False)
    if scope=='consumer':objects.contract(baseline,'root')
    else:objects.contract(baseline|dict(registry_ops=[dict(kind='lookup',name='dev_nand',type=23)]),'registry')
    return (ConsumerModel if scope=='consumer' else OpenModel)(c).run()


def native_vectors(scope='open'):
    ranges(scope);cases=[];base=objects.native_vectors('root' if scope=='consumer' else 'registry')['cases'][0]
    def op(kind='open',slot=None,**kw):return dict(kind=kind,slot=(3 if scope=='consumer' else 0) if slot is None else slot,flags=0x1234,query=0x1001,null_output=False,name='dev_nand',type=23)|kw
    def add(name,ops=None,**changes):
        c=base|dict(name=name,native_object_lifetime=True,registry_ops=[],life_ops=[op()] if ops is None else ops,life_tables=['all']*4,
            life_counts=[0]*4,life_open_status=0,life_ioctl_status=0,life_callback_write=True,life_irq=0,life_scheduler=0,life_acquire=0,life_release=0)|changes
        c['expected']=contract(c,scope);cases.append(c)
    if scope=='open':
        add('open_first_and_repeat',[op(),op(),op('ioctl')]);add('open_callback_error',life_open_status=-9)
        add('open_no_table',[op(),op('ioctl')],life_tables=['none']*4)
        add('open_no_callback',[op(),op('ioctl')],life_tables=['no_open']*4)
        add('open_existing_count',[op(),op('ioctl')],life_counts=[2,0,0,0],life_open_status=-9)
        add('open_negative_count',[op(),op('ioctl')],life_counts=[0xffffffff,0,0,0])
        add('open_signed_overflow',[op(),op('ioctl')],life_counts=[0x7fffffff,0,0,0])
        add('open_ioctl_closed',[op('ioctl')]);add('open_ioctl_missing',[op(),op('ioctl')],life_tables=['no_ioctl']*4)
        add('open_ioctl_error',[op(),op('ioctl')],life_ioctl_status=-9)
        add('open_ioctl_null_output',[op(),op('ioctl',null_output=True)])
        add('open_null',[op(slot=-1)]);add('open_ioctl_null',[op('ioctl',slot=-1)])
        add('open_register_then_open',[op('register_open'),op('ioctl')])
        add('open_registered_callback_error',[op('register_open'),op('ioctl')],life_open_status=-9)
        add('open_registered_duplicate',[op('register_open'),op('register_open'),op('ioctl')])
        add('open_registered_no_callback',[op('register_open'),op('ioctl')],life_tables=['no_open']*4)
    else:
        add('consumer_geometry',[op(),op('ioctl')]);add('consumer_geometry_alias',[op(),op('ioctl',query=0x1002)])
        add('consumer_repeat_open',[op(),op(),op('ioctl')]);add('consumer_not_open',[op('ioctl')])
        add('consumer_no_bbt',[op(),op('ioctl')],bbt_records={},bbt_record_hex={})
        add('consumer_query_noop',[op(),op('ioctl',query=0x1003,null_output=True)])
        add('consumer_query_invalid',[op(),op('ioctl',query=0x1000)])
        add('consumer_null_geometry',[op(),op('ioctl',null_output=True)])
        add('consumer_irq',[op(),op('ioctl')],life_irq=1)
        add('consumer_scheduler',[op(),op('ioctl')],life_scheduler=1)
        add('consumer_acquire_error',[op(),op('ioctl')],life_acquire=-9)
        add('consumer_release_error',[op(),op('ioctl')],life_release=-9)
        add('consumer_suspend_resume',[op(),op('suspend'),op('resume')])
        add('consumer_uid_error',[op(),op('ioctl')],uid_mismatch=True)
        add('consumer_root_alloc_error',[op(),op('ioctl')],root_alloc_fail=True)
    return dict(schema=1,bound_per_case=probe.lower.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    for address,name in function_names(scope):
        if memory.read(address,len(name)+1)!=name.encode()+b'\0':raise ValueError('original method name differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=probe.lower.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=probe.lower.BOUND:raise ValueError('native mismatch/bound')
    return dict(scope=scope,boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        function_names={f'{a:08x}':name for a,name in function_names(scope)},
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in ranges(scope)},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in data_ranges(scope)},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges(scope)},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original object open/register-open/ioctl policy executes; the open scope uses authored method tables/callbacks/reference counts, while consumer scope follows actual first-chip NAND root and original methods/geometry/context/chip queries.',
            'Post-root consumer calls, properties/heap/RTOS/library/peripheral effects and media streams are authored; open success or geometry publication is not physical I/O or safe ownership evidence.',
            'Closing/removal/reclamation and concurrent reference-count ownership remain unverified; negative/overflow counts are explicit fixtures, not observed device faults.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('open','consumer'),default='open')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect object lifetime: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
