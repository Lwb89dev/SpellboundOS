#!/usr/bin/env python3
"""Original object registry and driver-root startup joined to NAND probe/UID/BBT."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_probe_uid_stack as aux
else:
    import nand_probe_uid_stack as aux

probe=aux.probe
qspi=aux.qspi
HEAD=0x80d81f90
MUTEX=0x81260000
NODES=tuple(0x81320000+256*i for i in range(4))
NAME=0x81324000
PROPERTY=0x80d81b28
METHODS=0x80d811d8
REGISTRY_RANGES=((0x80c2ce64,104),(0x80c2cecc,276))
ROOT_RANGE=(0x80c27524,128)
ROOT_DATA=((PROPERTY,4),(0x80d811f4,28),(METHODS,28))


def ranges(scope):
    if scope=='registry':return probe.RANGES+REGISTRY_RANGES
    if scope=='root':return tuple(dict.fromkeys(aux.ranges('bbt')+REGISTRY_RANGES+(ROOT_RANGE,)))
    raise ValueError('object integration scope')


def data_ranges(scope):
    ranges(scope)
    base=probe.DATA_RANGES if scope=='registry' else aux.data_ranges('bbt')
    return tuple(dict.fromkeys(base+ROOT_DATA))


class RegistryMixin:
    def init_registry(self):
        self.nodes=[bytearray(b'\xa5'*60) for _ in NODES];self.linked=[]
        self.registry_mutex=MUTEX if self.c['registry_mutex_present'] else 0
        self.registry_creates=0;self.object_results=[];self.driver_root=0;self.root_heap_live=False
        self.regulator=0
        for seed in self.c['registry_seed']:
            slot=seed['slot'];b=self.nodes[slot];name=seed['name'].encode()
            b[:32]=name.ljust(32,b'\0');b[36]=seed['type'];self.linked.append(slot)
        for i,slot in enumerate(self.linked):
            struct.pack_into('<I',self.nodes[slot],52,NODES[self.linked[i+1]] if i+1<len(self.linked) else 0)
            struct.pack_into('<I',self.nodes[slot],56,HEAD if not i else NODES[self.linked[i-1]]+52)

    def object_lock(self):
        if not self.registry_mutex:
            values=self.c['registry_mutex_results'];value=values[min(self.registry_creates,len(values)-1)]
            self.registry_creates+=1;self.registry_mutex=value;self.actions.append(f'object_mutex_create:{value}')
        self.actions.append(f'object_lock:{self.registry_mutex}:{self.c["registry_lock_status"]}')

    def object_unlock(self):
        if self.registry_mutex:self.actions.append(f'object_unlock:{self.registry_mutex}:{self.c["registry_unlock_status"]}')

    def object_find(self,name,kind):
        self.actions.append(f'object_find_native:{kind}');self.object_lock();result=0
        query=name.encode().ljust(32,b'\0')[:32]
        for slot in self.linked:
            value=0
            for x,y in zip(self.nodes[slot][:32],query):
                value=x-y
                if value or x==0:break
            self.actions.append(f'object_compare:{slot}:{value}')
            if not value and self.nodes[slot][36]==kind:result=NODES[slot];break
        self.object_unlock();return result

    def object_register(self,slot,name,kind):
        self.actions.append(f'object_register_native:{slot}:{kind}')
        if slot<0 or name is None:
            self.actions.append('object_invalid')
            self.stopped=dict(kind='assertion',owner=0x80c3f614,line=0x7d);return None
        if self.object_find(name,kind):return -11
        self.object_lock();exists=slot in self.linked;self.object_unlock()
        if exists:return -11
        b=self.nodes[slot];b[36]=kind&255;struct.pack_into('<I',b,48,0)
        b[:32]=name.encode()[:31].ljust(32,b'\0');self.actions.append(f'object_zero:{slot}:32');self.actions.append(f'object_copy:{slot}:31')
        self.object_lock();struct.pack_into('<I',b,52,0)
        if self.linked:
            last=self.linked[-1];struct.pack_into('<I',self.nodes[last],52,NODES[slot]);previous=NODES[last]+52
        else:previous=HEAD
        struct.pack_into('<I',b,56,previous);self.linked.append(slot);self.object_unlock();return 0

    def finish_registry(self,result):
        result['rows'][0].update(object_head=NODES[self.linked[0]] if self.linked else 0,object_mutex=self.registry_mutex,
            object_nodes_hex={str(i):b.hex() for i,b in enumerate(self.nodes)},object_results=self.object_results,
            driver_root=self.driver_root,root_heap_live=self.root_heap_live)
        return result


class RegistryModel(RegistryMixin,probe.Model):
    def __init__(self,c):super().__init__(c);self.init_registry()
    def run_probe_entry(self):
        value=0
        for op in self.c['registry_ops']:
            value=self.object_find(op['name'],op['type']) if op['kind']=='lookup' else self.object_register(op['slot'],op['name'],op['type'])
            if self.stopped:break
            self.object_results.append(value&0xffffffff)
        return value
    def run(self):return self.finish_registry(super().run())


class RootModel(RegistryMixin,aux.BbtModel):
    def __init__(self,c):super().__init__(c);self.init_registry()
    def run_probe_entry(self):
        value=self.root_entry()
        if not self.stopped:
            self.object_results.append(value&0xffffffff)
            if self.c['root_follow_lookup']:self.object_results.append(self.object_find('dev_nand',23))
        return self.root_followups(value)
    def root_followups(self,value):
        return value
    def root_entry(self):
        present=self.c['root_property_present'];self.actions.append(f'root_property:{int(present)}');self.driver_root=PROPERTY if present else 0
        if not present:self.stopped=dict(kind='assertion',owner=0x80c3d208,line=0x31);return None
        self.regulator=probe.inventory.REGULATOR if self.c['probe_regulator_present'] else 0
        value=super().run_probe_entry()
        if self.stopped:return None
        if value:return -6
        self.root_heap_live=not self.c['root_alloc_fail'];self.actions.append(f'root_alloc:60:{NODES[3] if self.root_heap_live else 0}')
        if not self.root_heap_live:return -6
        self.nodes[3][:]=bytes(60);self.actions.append('object_zero:3:60');struct.pack_into('<I',self.nodes[3],40,METHODS)
        return self.object_register(3,'dev_nand',23)
    def run(self):return self.finish_registry(super().run())


def contract(c,scope):
    ranges(scope)
    if not c['native_object_registry'] or c['native_nand_root']!=(scope=='root'):raise ValueError('object entry flags')
    if len(c['registry_seed'])>3 or len(c['registry_ops'])>8:raise ValueError('object fixture bound')
    slots=[]
    def name(value,maximum):
        if not isinstance(value,str) or not value.isascii() or '\0' in value or len(value)>maximum:raise ValueError('object name')
    for seed in c['registry_seed']:
        if not 0<=seed['slot']<3 or seed['slot'] in slots or not 0<=seed['type']<=255:raise ValueError('seeded object')
        name(seed['name'],32);slots.append(seed['slot'])
    for op in c['registry_ops']:
        if op['kind'] not in ('register','lookup') or not 0<=op['type']<=65535:raise ValueError('object operation')
        if op['kind']=='register' and not -1<=op['slot']<3:raise ValueError('object slot')
        if op['kind']=='lookup' or op['name'] is not None:name(op['name'],64)
    if not 1<=len(c['registry_mutex_results'])<=4 or any(v not in (0,MUTEX) for v in c['registry_mutex_results']):raise ValueError('mutex backing')
    if any(not -100<=c[k]<=0 for k in ('registry_lock_status','registry_unlock_status')):raise ValueError('mutex service status')
    if scope=='root':
        if c['registry_ops'] or c['probe_entry']!='wrapper':raise ValueError('root callback scope')
        aux.contract(c,'bbt')
    else:
        if not c['registry_ops'] or c.get('native_bbt_stack',False) or c.get('native_identity',False):raise ValueError('direct registry scope')
        probe.contract(c)
    return (RootModel if scope=='root' else RegistryModel)(c).run()


def native_vectors(scope='registry'):
    ranges(scope);cases=[]
    base=(aux.native_vectors('bbt') if scope=='root' else probe.native_vectors())['cases'][0]
    def op(slot=0,name='dev_nand',kind=23):return dict(kind='register',slot=slot,name=name,type=kind)
    def find(name='dev_nand',kind=23):return dict(kind='lookup',name=name,type=kind)
    def seed(slot=0,name='other',kind=23):return dict(slot=slot,name=name,type=kind)
    def add(label,ops=None,**changes):
        c=base|dict(name=label,native_object_registry=True,native_nand_root=scope=='root',probe_entry='wrapper',
            registry_ops=[] if ops is None else ops,registry_seed=[],registry_mutex_present=False,registry_mutex_results=[MUTEX],
            registry_lock_status=0,registry_unlock_status=0,root_alloc_fail=False,root_property_present=True,root_follow_lookup=True)|changes
        c['expected']=contract(c,scope);cases.append(c)
    if scope=='registry':
        add('object_empty_lookup',[find()]);add('object_first_insert',[op(),find()])
        add('object_append_three',[op(0,'a'),op(1,'b'),op(2,'c'),find('c')])
        add('object_duplicate_name',[op(),op(1),find()])
        add('object_duplicate_pointer',[op(),op(0,'renamed'),find('renamed'),find()])
        add('object_same_name_other_type',[op(),op(1,kind=22),find(kind=22),find()])
        add('object_seeded_append',[op(),find()],registry_seed=[seed(1,'one'),seed(2,'two')])
        add('object_seeded_duplicate',[op(),find()],registry_seed=[seed(1,'dev_nand')])
        add('object_existing_mutex',[op(),find()],registry_mutex_present=True)
        add('object_mutex_retry',[op(),find()],registry_mutex_results=[0,MUTEX],registry_lock_status=-9)
        add('object_no_mutex',[op(),find()],registry_mutex_results=[0],registry_lock_status=-9)
        add('object_lock_errors',[op(),find()],registry_lock_status=-9,registry_unlock_status=-9)
        add('object_name_31',[op(name='x'*31),find('x'*31)])
        add('object_name_32',[op(name='x'*32),find('x'*32),find('x'*31)])
        add('object_long_duplicate',[op(name='x'*32),op(1,'x'*32),find('x'*31)])
        add('object_type_truncation',[op(kind=279),find(kind=279),find(kind=23),op(1,kind=279)])
        add('object_empty_name',[op(name=''),find('')])
        add('object_null_pointer',[op(-1)]);add('object_null_name',[op(name=None)])
    else:
        add('root_ready');add('root_append',registry_seed=[seed()])
        add('root_duplicate_name',registry_seed=[seed(name='dev_nand')])
        add('root_other_type',registry_seed=[seed(name='dev_nand',kind=22)])
        add('root_alloc_failure',root_alloc_fail=True);add('root_property_missing',root_property_present=False)
        add('root_uid_error_export',uid_mismatch=True,aux_export_uid=True)
        add('root_no_bbt',bbt_records={},bbt_record_hex={})
        add('root_feature_error',probe_feature_mismatch_at=3)
        add('root_driver_mutex_failure',probe_mutex_fail=True)
        add('root_bbt_assertion',bbt_good_blocks=[],bbt_records={},bbt_record_hex={})
        add('root_registry_mutex_failure',registry_mutex_results=[0],registry_lock_status=-9)
        add('root_existing_mutexes',probe_mutex_present=True,registry_mutex_present=True)
        bad=next(c for c in aux.native_vectors('bbt')['cases'] if c['name']=='uid_bbt_erase_error')
        add('root_repair_failure',**{k:bad[k] for k in ('bbt_records','bbt_record_hex','responses')})
    return dict(schema=1,bound_per_case=probe.lower.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=probe.lower.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=probe.lower.BOUND:raise ValueError('native mismatch/bound')
    return dict(scope=scope,boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in ranges(scope)},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in data_ranges(scope)},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges(scope)},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original object lookup/register and optional NAND driver-root/probe/UID/BBT bodies execute; locks/heap/property/library/peripheral effects and media streams are authored.',
            'Mutex failure cases let supplied lock services return errors, rather than executing a real RTOS with a null handle; concurrency and actual failure handling are not established.',
            'Original registration links and publication are RAM evidence over authored objects, not persistent media reconstruction, physical driver operation or standalone boot.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('registry','root'),default='registry')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND object integration: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
