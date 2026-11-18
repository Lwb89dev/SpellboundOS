#!/usr/bin/env python3
"""Main NAND geometry/context/chip queries and root/registry/PM publication."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_object_lifecycle as base
else:
    import main_object_lifecycle as base

MAGIC=0x746242
CHIPS=(dict(address=0x70a3204c,id=0xbaef,pages=65536,page_size=2048),dict(address=0x70a318b0,id=0xb2ef,pages=131072,page_size=4096))
ROOT=0x70f8e6e0
CACHE=0x70f8e6dc
MUTEX=0x70f8e6e4
SELECTED=0x70f8e6f8
BBT=0x70f9bbac
HEAD=0x70f8ead0
REG_MUTEX=0x70f8ead4
HANDLE=0x81270000
REG_HANDLE=0x81271000
SEED=0x8132b000
PM=0x8132c000
NAME=0x8132d000
PM_COOKIE=0x12345678
LOWER=((0x702d5b32,36),(0x702d5ba4,66),(0x702d5be6,64),(0x702d5c26,64),(0x702d7414,412),(0x702d5ad2,24))
ROOT_RANGES=((0x702d54c6,280),(0x702d5b56,78),(0x70319252,120),(0x703192ca,312))
SWITCH=0x70a315d8


def ranges(scope):
    if scope not in ('geometry','root'):raise ValueError('main NAND stack scope')
    return base.ranges('nand')+LOWER+(ROOT_RANGES if scope=='root' else ())


def data_ranges(scope):
    ranges(scope)
    return tuple(dict.fromkeys(base.data_ranges('nand')+tuple((c['address'],184) for c in CHIPS)+((SWITCH,124),)+
        (((0x709bd0c8,12),(0x70a30c34,13),(0x70a441fc,17)) if scope=='root' else ())))


class Model(base.Model):
    def __init__(self,c,scope):
        super().__init__(c,'nand');self.stack_scope=scope;self.chip=CHIPS[c['main_chip_index']]
        self.selected=self.chip['address'] if c['main_chip_present'] and scope=='geometry' else 0
        self.driver_mutex=HANDLE if c['main_mutex_present'] else 0;self.root=0;self.cache=0;self.heap_live=False;self.pm_calls=0
        self.reg_mutex=REG_HANDLE if c['main_reg_mutex_present'] else 0
        self.seed=bytearray(b'\xa5'*60);self.head=0
        if c['main_seed']!='none':
            self.seed[:32]=(b'dev_nand' if c['main_seed']=='duplicate' else b'other').ljust(32,b'\0');self.seed[36]=23
            struct.pack_into('<II',self.seed,52,0,HEAD);self.head=SEED
        if scope=='root':self.obj[:]=b'\xa5'*60
    def query(self,q,index):
        c=self.c;self.lower_calls+=1;self.actions.append(f'main_lower_native:{q}');self.actions.append(f'main_irq:{c["main_irq"]}')
        direct=bool(c['main_irq'])
        if not direct:self.actions.append(f'main_scheduler:{c["main_scheduler"]}');direct=bool(c['main_scheduler'])
        if not direct and self.driver_mutex:
            status=c['main_acquire'];self.actions.append(f'main_acquire:{status}')
            if status:self.stopped=dict(kind='assertion',owner=0x70a30f20,line=36);return None,None
        self.actions.append(f'main_chip_native:{q}')
        status=0 if self.selected else -2
        if status:self.actions.append('log:main_chip_error');value=None
        else:value={13:self.chip['id'],2:self.chip['page_size'],1:self.chip['pages'],14:int(c['main_bbt_magic']==MAGIC)}[q]
        if not direct and self.driver_mutex:
            result=c['main_release'];self.actions.append(f'main_release:{result}')
            if result:self.stopped=dict(kind='assertion',owner=0x70a30f08,line=42);return None,None
        return status,value
    def reg_lock(self):
        if not self.reg_mutex:self.reg_mutex=REG_HANDLE;self.actions.append(f'main_reg_mutex_create:{REG_HANDLE}')
        self.actions.append('main_reg_lock')
    def reg_unlock(self):self.actions.append('main_reg_unlock')
    def register(self):
        self.actions.append('main_register_native');self.actions.append('main_find_native');self.reg_lock()
        result=0
        if self.head:
            name=b'dev_nand\0';value=0
            for x,y in zip(self.seed,name):
                value=x-y
                if value or not x:break
            self.actions.append(f'main_compare:{value}')
            result=SEED if not value else 0
        self.reg_unlock()
        if result:return -11
        self.reg_lock();self.reg_unlock();self.obj[:32]=bytes(32);self.actions.append('main_zero:32');self.obj[:32]=b'dev_nand'.ljust(32,b'\0');self.actions.append('main_name_copy:31');self.obj[36]=23;self.count(0)
        self.reg_lock();struct.pack_into('<I',self.obj,52,0)
        if self.head:struct.pack_into('<I',self.seed,52,base.OBJECT);previous=SEED+52
        else:self.head=base.OBJECT;previous=HEAD
        struct.pack_into('<I',self.obj,56,previous);self.reg_unlock();return 0
    def initialize(self):
        c=self.c;present=c['main_property'];self.actions.append(f'main_property:{int(present)}');self.root=base.PROPERTY if present else 0
        if not present:self.stopped=dict(kind='assertion',owner=0x70a30c88,line=49);return None
        status=self.probe()
        if self.stopped:return None
        if not status:
            if not self.driver_mutex:
                self.driver_mutex=0 if c['main_mutex_fail'] else HANDLE;self.actions.append(f'main_driver_mutex_create:{self.driver_mutex}')
                if not self.driver_mutex:self.stopped=dict(kind='assertion',owner=0x70a30ef0,line=30);return None
        if status:return -6
        self.heap_live=not c['main_alloc_fail'];self.actions.append(f'main_alloc:{base.OBJECT if self.heap_live else 0}')
        if not self.heap_live:return -6
        self.obj[:]=bytes(60);self.actions.append('main_zero:60');struct.pack_into('<I',self.obj,40,base.METHODS)
        status=self.register()
        if status:return status
        self.cache=base.OBJECT;self.actions.append('main_pm_property:'+str(int(c['main_pm_property'])))
        if not c['main_pm_property']:
            self.actions.append('diagnostic:initialize');self.stopped=dict(kind='assertion',owner=0x70a30c60,line=31);return None
        self.pm_calls+=1;self.actions.append(f'main_pm_register:{c["main_pm_status"]}');return 0
    def probe(self):
        status=self.c['main_probe_status'];self.actions.append(f'main_probe:{status}')
        if not status:self.selected=self.chip['address'] if self.c['main_chip_present'] else 0
        return status
    def operation(self,op):
        if op['op']=='initialize':self.actions.append('native:initialize');return self.initialize()
        return super().operation(op)
    def run(self):
        for op in self.c['operations']:
            value=self.operation(op);self.rows.append(dict(returned=None if self.stopped else value&0xffffffff,stopped=self.stopped,
                object_hex=self.obj.hex(),output_hex=self.output.hex(),data_sha256=base.digest(self.data),lower_calls=self.lower_calls,
                main_selected=self.selected,main_mutex=self.driver_mutex,main_bbt_magic=self.c['main_bbt_magic'],main_root=self.root,
                main_cache=self.cache,main_heap_live=self.heap_live,main_head=self.head,main_registry_mutex=self.reg_mutex,
                main_seed_hex=self.seed.hex(),main_pm_calls=self.pm_calls))
            if self.stopped or op['op']=='initialize' and value:break
        return dict(actions=self.actions,rows=self.rows)


def contract(c,scope):
    ranges(scope)
    if not c['native_main_lower'] or c['native_main_root']!=(scope=='root') or c['main_chip_index'] not in (0,1):raise ValueError('main stack entry')
    if c['main_seed'] not in ('none','other','duplicate') or not 0<=c['main_bbt_magic']<=0xffffffff:raise ValueError('main state')
    if any(c[k] not in (0,1) for k in ('main_irq','main_scheduler')) or any(not -100<=c[k]<=100 for k in ('main_acquire','main_release','main_probe_status','main_pm_status')):raise ValueError('main services')
    ops=c['operations']
    if not 1<=len(ops)<=12:raise ValueError('main stack operation bound')
    if scope=='root' and (ops[0]['op']!='initialize' or any(op['op']=='initialize' for op in ops[1:])):raise ValueError('root sequence')
    if scope=='geometry' and any(op['op']=='initialize' for op in ops):raise ValueError('geometry scope')
    filtered=[op for op in ops if op['op']!='initialize']
    base.contract(c|dict(operations=filtered or [dict(op='active',object=True,data=True,output=True,command=1,flags=0,offset=0,size=0)]),'nand')
    return Model(c,scope).run()


def native_vectors(scope='geometry'):
    ranges(scope);cases=[];initial=base.native_vectors('nand')['cases'][0]
    def op(kind,**changes):return dict(op=kind,object=True,data=True,output=True,command=0x1001,flags=0x1234,offset=5,size=8)|changes
    def add(name,ops=None,**changes):
        ops=([op('initialize')] if scope=='root' else [])+([op('open'),op('ioctl'),op('close')] if ops is None else ops)
        c=initial|dict(name=name,operations=ops,native_main_lower=True,native_main_root=scope=='root',main_chip_index=0,
            main_chip_present=True,main_bbt_magic=MAGIC,main_mutex_present=scope=='geometry',main_irq=0,main_scheduler=0,
            main_acquire=0,main_release=0,main_property=True,main_probe_status=0,main_mutex_fail=False,main_alloc_fail=False,
            main_seed='none',main_reg_mutex_present=False,main_pm_property=True,main_pm_status=0)|changes
        c['expected']=contract(c,scope);cases.append(c)
    if scope=='geometry':
        add('main_stack_geometry');add('main_stack_four_kib',main_chip_index=1)
        add('main_stack_no_bbt',main_bbt_magic=0);add('main_stack_bad_magic',main_bbt_magic=1)
        add('main_stack_no_chip',main_chip_present=False);add('main_stack_irq',main_irq=1)
        add('main_stack_scheduler',main_scheduler=1);add('main_stack_no_mutex',main_mutex_present=False)
        add('main_stack_acquire_error',main_acquire=-9);add('main_stack_release_error',main_release=-9)
        add('main_stack_alias',[op('open'),op('ioctl',command=0x1002)])
        add('main_stack_noop',[op('open'),op('ioctl',command=0x1003,output=False)])
        add('main_stack_null_output',[op('open'),op('ioctl',output=False)])
    else:
        add('main_root_ready');add('main_root_append',main_seed='other');add('main_root_duplicate',main_seed='duplicate')
        add('main_root_probe_error',main_probe_status=-9);add('main_root_alloc_error',main_alloc_fail=True)
        add('main_root_no_property',main_property=False);add('main_root_mutex_error',main_mutex_fail=True)
        add('main_root_no_pm_property',main_pm_property=False);add('main_root_pm_error_ignored',main_pm_status=-9)
        add('main_root_existing_mutexes',main_mutex_present=True,main_reg_mutex_present=True)
        add('main_root_no_bbt',main_bbt_magic=0);add('main_root_four_kib',main_chip_index=1)
    return dict(schema=1,scope='nand',bound_per_case=base.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=base.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=base.BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges(scope)},
        data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges(scope)},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges(scope)},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main generic/NAND-method/context/chip geometry and BBT-active bodies execute over authored selected-chip/mutex/magic state; no actual media or probe is established.',
            'Root scope joins original initializer/wrapper/registry/PM publication with supplied probe, BSP property, heap, RTOS, bounded library and PM-registration services.',
            'Publication/callback status and geometry do not establish physical chip identity, valid BBT provenance, ownership/reclamation, concurrency or standalone boot.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('geometry','root'),default='geometry')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main NAND stack: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
