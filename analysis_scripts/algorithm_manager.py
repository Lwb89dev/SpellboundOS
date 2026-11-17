#!/usr/bin/env python3
"""Bounded main algorithm registration/lifetime and actual HR adapter contracts.

Mathematical initialization/processing/teardown and extension hooks are supplied.
The real HR configuration copier and uninitialized processing guard can execute.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .cache_receiver import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    from cache_receiver import image_memory
    from zrpc_packets import MAIN_HASH

TABLE=0x70fc1ffc
HR=0x70f638e0
RECORDS=0x81010000
DESC=0x81020000
WORK=0x81021000
OUTPUT=0x81022000
CONTROL=0x81023000
CB=0x70000100
STATE=0x80c46120
CONFIG=dict(base_reg=0x704c4a24,reg=0x704c4cb6,enable=0x704c4d3c,disable=0x704c4d40,
            lookup=0x704c4c3a,active=0x704c4c0c,dispatch=0x704c4d44,control=0x704c4e00,
            mask=0x704c4e58,hr_register=0x7031348e,hr_process=0x7089b82c,
            hr_init=0x7089adca,hr_exit=0x7089b360,extension=0x7089a252,
            copy=0x70947c08,zero=0x70947ce8,logger=0x702b38a2)
RANGES=((0x704c4a1e,0x46a),(0x70313446,0x5a),(0x7089d110,0x25c),(0x7089b82c,0xb8))
TARGETS=(0x704c4a1e,0x704c4a22,0x704c4a24,0x704c4ac2,0x704c4b86,0x704c4c0c,0x704c4c3a,
         0x704c4cb6,0x704c4d3c,0x704c4d40,0x704c4d44,0x704c4e00,0x704c4e58,
         0x70313446,0x7031345a,0x70313470,0x70313478,0x7031348e,0x7089b82c,0x7089adca,0x7089d110)
LOGS={0x70c02f04:'reg_invalid',0x70c02f40:'reg_duplicate',0x70c03004:'ops_invalid',0x70c0303c:'ops_reg_failed',
      0x70c02f74:'enable_missing',0x70c02fa8:'enable_error',0x70c02fd0:'disable_missing',
      0x70c0305c:'dispatch_invalid',0x70c03094:'dispatch_missing',0x70c030cc:'dispatch_error',0x70c030f0:'control_error',
      0x70d1ad34:'hr_config',0x70d1ad50:'hr_config_array1',0x70d1ad78:'hr_config_array0',0x70d1ada4:'hr_config_array2',
      0x70d1add0:'hr_config_tail',0x70d1addc:'hr_extension_nonone',0x70d1ae04:'hr_extension_absent',0x70d1a1d4:'hr_uninitialized'}


def digest(data):return hashlib.sha256(data).hexdigest()
def put(data,offset,size,value):data[offset:offset+size]=value.to_bytes(size,'little')
def word(data,offset,size=4):return int.from_bytes(data[offset:offset+size],'little')
def valid_id(value):return 0x1001<=value<=0x1039
def record_address(index,definition):return HR if definition.get('real') else RECORDS+0x100*index


def record_bytes(definition):
    if definition.get('real'):
        return bytearray(struct.pack('<12I',0x70a4347c,0x70a43464,0x100d,0,0x70313478,0x70313470,
                                     0x82012,0,0,0x7031345a,0x70313446,0))
    if not 0<=definition['id']<=65535:raise ValueError('registration IDs must fit 16 bits')
    return bytearray(struct.pack('<12I',0,0,definition['id'],definition.get('refs',123),
        CB if definition.get('init',True) else 0,CB+4 if definition.get('exit',True) else 0,
        definition.get('mask',0x10)&0xffffffff,definition.get('mask',0x10)>>32,0,
        CB+8 if definition.get('process',True) else 0,CB+12 if definition.get('control',True) else 0,0))


def apply_hr_control(state,source,extension_status):
    if len(source)!=48:raise ValueError('HR control must have 48 bytes')
    state[:56]=bytes(56)
    state[:6]=source[:6]
    state[7:38]=source[7:38]
    state[0x9d]=source[6]
    state[0x9c]=int(word(source,40)==0 or extension_status!=1)
    return ['log:hr_config','log:hr_config_array1','log:hr_config_array0','log:hr_config_array2','log:hr_config_tail']


def contract(case):
    definitions=case['records'];records=[record_bytes(d) for d in definitions]
    pointers=[record_address(i,d) for i,d in enumerate(definitions)]
    table=bytearray(58*8);state=bytearray(b'\x5a'*160);state[0x9e]=0
    output=bytearray(b'\xa5'*0x520);actions=[];rows=[]
    def lookup(identifier):
        if not valid_id(identifier):return None
        ptr=word(table,(identifier-0x1000)*8)
        return pointers.index(ptr) if ptr else None
    for op in case['operations']:
        kind=op['op'];status=op.get('status',0);identifier=op.get('id',0x100d);returned=None
        if not 0<=identifier<=65535:raise ValueError('lookup IDs beyond 16 bits are excluded')
        if kind in ('reg','base_reg','hr_register'):
            index=op.get('record',0);raw=None if index is None else records[index]
            ops=kind!='base_reg'
            if raw is None or (ops and not word(raw,36)):
                if ops:actions.append('log:ops_invalid')
                else:returned=0
            else:
                alg=word(raw,8,2)
                error='reg_invalid' if not valid_id(alg) else ('reg_duplicate' if lookup(alg) is not None else None)
                if error:
                    actions.append('log:'+error)
                    if ops:actions.append('log:ops_reg_failed')
                    else:returned=0
                else:
                    put(raw,12,2,0)
                    if not word(raw,16):put(raw,16,4,0x704c4a1e)
                    if not word(raw,20):put(raw,20,4,0x704c4a22)
                    put(table,(alg-0x1000)*8,4,pointers[index]);table[(alg-0x1000)*8+4]=0
                    if not ops:returned=pointers[index]
        elif kind=='seed':
            index=lookup(identifier)
            if index is None:raise ValueError('seed requires registered record')
            put(records[index],12,2,op['refs']);table[(identifier-0x1000)*8+4]=op['enabled']
            actions.append('supplied:seed')
        elif kind in ('enable','disable'):
            index=lookup(identifier)
            if index is None:
                actions.append('log:'+kind+'_missing')
                if kind=='enable':returned=1
            else:
                raw=records[index];at=(identifier-0x1000)*8+4;refs=word(raw,12,2)
                if kind=='enable':
                    put(raw,12,2,(refs+1)&65535);returned=0
                    if not table[at]:
                        callback=word(raw,16)
                        if callback!=0x704c4a1e:actions.append('backend:init' if definitions[index].get('real') else 'callback:init')
                        result=(int(status!=0) if definitions[index].get('real') else status) if callback!=0x704c4a1e else 0
                        if result:actions.append('log:enable_error');returned=result
                        else:table[at]=1
                else:
                    if refs:refs-=1;put(raw,12,2,refs)
                    if table[at] and refs==0:
                        if word(raw,20)!=0x704c4a22:actions.append('backend:exit' if definitions[index].get('real') else 'callback:exit')
                        table[at]=0
        elif kind in ('lookup','active'):
            index=lookup(identifier)
            returned=(pointers[index] if index is not None else 0) if kind=='lookup' else (table[(identifier-0x1000)*8+4] if valid_id(identifier) else 0)
        elif kind=='mask':
            index=lookup(identifier)
            if index is not None:put(records[index],24,8,op['mask'])
        elif kind=='dispatch':
            if op.get('output',True):
                output[0]=0;put(output,2,2,identifier&65535)
                index=lookup(identifier)
                active=table[(identifier-0x1000)*8+4] if valid_id(identifier) else 0
                if active:
                    if index is None:raise ValueError('unmodeled corrupt active slot')
                    typ=op.get('type',0x10)
                    if typ is None or word(records[index],24,8)&typ:
                        if definitions[index].get('real'):
                            actions.append('backend:process')
                            if op.get('real_guard'):
                                actions.append('log:hr_uninitialized');result=1
                            else:
                                output[0]=int(op.get('ready',True));output[8]=72;output[9]=4;result=int(status!=0)
                        else:
                            actions.append('callback:process');output[0]=int(op.get('ready',True));output[8]=72;output[9]=4;result=status
                        if result:actions.append('log:dispatch_error')
            else:actions.append('log:dispatch_invalid')
        elif kind in ('control','direct_control'):
            index=lookup(identifier)
            if kind=='direct_control' or (index is not None and word(records[index],40)):
                if kind=='direct_control' or definitions[index].get('real'):
                    source=bytes.fromhex(op['control_hex']);actions.extend(apply_hr_control(state,source,status))
                    if word(source,40):
                        actions.append('backend:extension')
                        if status!=1:actions.append('log:hr_extension_nonone')
                        if kind=='direct_control':returned=1 if status==1 else 0
                    else:
                        actions.append('log:hr_extension_absent')
                        if kind=='direct_control':returned=0
                else:
                    actions.append('callback:control')
                    if status:actions.append('log:control_error')
        else:raise ValueError('unsupported algorithm operation')
        rows.append(dict(returned=returned,table_sha256=digest(table),record_sha256=[digest(raw) for raw in records],
                         output_sha256=digest(output),state_sha256=digest(state)))
    return dict(actions=actions,rows=rows)


def control_bytes(extension=False,seed=1):
    raw=bytearray((seed+i*7)&255 for i in range(48));put(raw,40,4,0x81024000 if extension else 0);put(raw,44,4,16)
    return raw.hex()


def native_vectors():
    cases=[]
    def op(kind,**args):return dict(op=kind,**args)
    reg=op('reg');hr=op('hr_register');start=op('enable');stop=op('disable');send=op('dispatch')
    generic=dict(id=0x100d)
    def add(name,operations,records=None):
        c=dict(name=name,records=records if records is not None else [dict(real=True)],operations=operations)
        c['expected']=contract(c);cases.append(c)
    add('register_real_hr',[hr,op('lookup'),op('active')])
    add('register_duplicate_real',[hr,reg])
    add('register_duplicate_other',[reg,op('base_reg',record=1)],[generic,generic|dict(refs=456)])
    add('register_null',[op('reg',record=None),op('base_reg',record=None)])
    add('register_missing_process',[reg],[generic|dict(process=False)])
    add('register_base_missing_process',[op('base_reg')],[generic|dict(process=False)])
    add('register_default_lifecycle',[reg,start,start,stop,stop],[generic|dict(init=False,exit=False)])
    for identifier in (0,0x1000,0x103a,0xffff):add('register_invalid_'+hex(identifier),[reg],[dict(id=identifier)])
    for identifier in (0x1001,0x1039):add('register_edge_'+hex(identifier),[op('base_reg'),op('lookup',id=identifier),op('enable',id=identifier),op('disable',id=identifier)],[dict(id=identifier)])
    add('lookup_missing',[op('lookup'),op('active'),op('lookup',id=0x103a),op('active',id=0x1000)])
    add('hr_lifetime_two_owners',[hr,start,start,stop,stop,stop])
    add('hr_init_error_retries',[hr,op('enable',status=7),op('enable',status=0xffffffff),start,stop,stop,stop])
    add('hr_failed_init_then_disable',[hr,op('enable',status=9),stop,start,stop])
    add('generic_init_error_preserved',[reg,op('enable',status=7),stop],[generic])
    add('lifetime_missing',[start,stop,op('enable',id=0x103a),op('disable',id=0x1000)])
    add('lifetime_zero_refs_active',[hr,op('seed',refs=0,enabled=2),stop])
    add('lifetime_wrap',[hr,start,op('seed',refs=65535,enabled=1),start,stop])
    add('hr_exit_status_ignored',[hr,start,op('disable',status=0xdeadbeef)])
    add('dispatch_disabled',[hr,send])
    for typ in (2,0x10,0x2000,0x80000,0x8000,1):add('dispatch_type_'+hex(typ),[hr,start,op('dispatch',type=typ),stop])
    add('dispatch_error_normalized',[hr,start,op('dispatch',status=0xffffffff),stop])
    add('dispatch_real_uninitialized_guard',[hr,start,op('dispatch',real_guard=True),stop])
    add('dispatch_generic_error',[reg,start,op('dispatch',status=7),stop],[generic])
    add('dispatch_null_output',[hr,start,op('dispatch',output=False),stop])
    add('dispatch_missing',[send,op('dispatch',id=0x103a)])
    add('dispatch_no_ready',[hr,start,op('dispatch',ready=False),stop])
    add('dispatch_null_descriptor',[hr,start,op('mask',mask=0),op('dispatch',type=None),stop])
    add('dispatch_mask_mutation',[hr,start,op('mask',mask=1<<32),send,op('dispatch',type=1<<32),op('mask',mask=0),send,stop])
    add('mask_missing',[op('mask',mask=1<<32),op('mask',id=0x103a,mask=7)])
    for extension,status in ((False,0),(True,0),(True,1),(True,7)):
        add('control_real_'+str(extension)+'_'+str(status),[hr,op('control',control_hex=control_bytes(extension),status=status)])
    add('control_enabled',[hr,start,op('control',control_hex=control_bytes()),stop])
    add('control_repeated',[hr,op('control',control_hex=control_bytes(True),status=1),op('control',control_hex=control_bytes(seed=99))])
    add('control_missing',[op('control',control_hex=control_bytes())])
    add('control_no_callback',[reg,op('control',control_hex=control_bytes())],[generic|dict(control=False)])
    add('control_generic_error',[reg,op('control',control_hex=control_bytes(),status=7)],[generic])
    add('control_direct_success',[op('direct_control',control_hex=control_bytes(True),status=1)])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from model')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive,'main')
    if memory.read(HR,48)!=record_bytes(dict(real=True)):raise ValueError('unexpected HR registration record')
    return dict(main_sha256=MAIN_HASH,hr_record_sha256=digest(memory.read(HR,48)),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),native_validation=execution,
        native_steps=sum(row['steps'] for row in execution['cases']),
        limitations=['OS/concurrency/hardware and real mathematical initialization, processing and teardown are not executed.',
            'The actual HR record, registration/lifetime/dispatch adapters, configuration copier and uninitialized processing guard execute.',
            'Extension callback, copy/zero helpers and logger return zero are supplied; inputs and caller sequences are synthetic.',
            'Public lookup IDs are bounded to 16 bits; full engine activation, motion/minute/wear/reset consumers and measurement accuracy remain open.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive, vectors, validation and decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect algorithm manager: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
