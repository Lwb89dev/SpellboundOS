#!/usr/bin/env python3
"""Boot environment wrappers, reason/key policy and stopped upgrade-record caller.

Storage, locks, board/keyboard/delay services are supplied. The boot caller stops
before recovery/UI dispatch; no environment or flash is changed on a device.
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

KEY=0x81200000
DATA=0x81210000
INPUT=0x81220000
OUTPUT=0x81230000
LENGTH=0x81240000
CACHE=0x80de6294
NEW=0x80de62cc
READY=0x80d81d40
MAINTENANCE=0x80d81d3f
REASON=0x80d81afc
RETAINED=0x80dff738
KEYBOARD=0x80d81ce8
STOP=0x80c005b8
BACKUP='/mnt/backup/backup_fw_sign.zip'
CONFIG=dict(get=0x80c0d344,set=0x80c0d3b4,commit=0x80c0d490,reason=0x80c0ec70,key=0x80c00312,prefix=0x80c00454,
    lock=0x80c0c0f6,unlock=0x80c0c108,find=0x80c0cdf6,read=0x80c0bf58,reserve=0x80c0cb7a,
    append=0x80c0cbca,remove=0x80c0ced6,maintenance=0x80c0cb16,strlen=0x80c2e57c,warn=0x80c0c220,
    raw_reason=0x80c12244,copy=0x80c2de38,keyboard_command=0x80c2d0ba,power=0x80c216ac,delay=0x80c16884,
    zero=0x80c2e014,strncpy=0x80c2e684,logger=0x80c1cd7a,board_flag=0x80c01848,display=0x80c00a22,
    hw=0x80c1c608,board_init=0x80c0192e,keyboard_register=0x80c2ce46,keyboard_init=0x80c2d04e)
RANGES=((0x80c0d344,0x150),(0x80c0ec70,0x80),(0x80c00312,0x2f8),(0x80c01884,0x1a))
TARGETS=(0x80c0d344,0x80c0d3b4,0x80c0d490,0x80c0ec70,0x80c00312,0x80c01884,0x80c00450,0x80c00454)
LOGS={0x80c32aa8:'reason',0x80c32ac0:'no_power',0x80c32af0:'press',0x80c32ad8:'key_pass',
      0x80c32b08:'build',0x80c32b30:'hw',0x80c32b50:'backup_request',0x80c32b6c:'fallback_reason'}


def put(data,at,value):struct.pack_into('<I',data,at,value&0xffffffff)
def upgrade_record():
    data=bytearray(298);put(data,0,0xb007cca6);put(data,4,298);struct.pack_into('<H',data,8,0x102)
    data[42]=1;data[43:43+len(BACKUP)]=BACKUP.encode();return data


class Model:
    def __init__(self,c):
        self.c=c;self.actions=[];self.buffer=bytearray(b'\xa5'*1024);self.length=0xa5a5a5a5;self.descriptor=bytearray(b'\xa5'*56)
        self.flag=c['maintenance_required'];self.cached=c['cached_reason'];self.polls=0;self.appends=[];self.keyboard=c['keyboard_initial'];self.stopped=None
    def find(self,global_record=False):
        ok=self.c['found'];self.actions.append('env:find:'+str(int(ok)))
        if ok and global_record:
            self.descriptor[:]=bytes(56);put(self.descriptor,12,len(bytes.fromhex(self.c['stored_hex'])));put(self.descriptor,52,DATA)
        return ok
    def get(self):
        c=self.c
        if not c['ready']:self.actions.append('env:uninitialized');return 0
        self.actions.append('env:lock');n=0
        if not self.find():
            if c['size_output']:self.length=0
        else:
            source=bytes.fromhex(c['stored_hex']);n=min(c['capacity'],len(source))
            if c['size_output']:self.length=len(source)
            if c['has_output']:
                self.actions.append(f'env:read:{n}:{c["read_status"]}')
                if c['read_status']==0:self.buffer[:n]=source[:n]
        self.actions.append('env:unlock');return n
    def remove(self,kind):
        status=self.c['remove_'+kind];self.actions.append(f'env:remove:{kind}:{status}');return status
    def set(self,payload,key=None,delete=False):
        c=self.c;key=c['key_name'] if key is None else key
        if not c['ready']:self.actions.append('env:uninitialized');return 7
        self.actions.append('env:lock')
        if delete:result=self.remove('direct')
        else:
            self.actions.append('env:reserve:'+str(len(payload)+28+len(key)))
            if c['reserve_result']==0xffffffff:result=6
            else:
                found=self.find(True);result=self.remove('mark') if found else 0
                if not result:
                    result=c['append_status'];self.actions.append('env:append:'+str(result));self.appends.append(dict(key=key,size=len(payload),sha256=digest(payload),status=result))
                    if found and not result:result=self.remove('final')
                if self.flag:self.actions.append('env:maintenance');self.flag=0
        self.actions.append('env:unlock');return result
    def reason(self):
        if self.cached!=0xffffffff:return self.cached
        self.actions.extend(['reason:raw','reason:retained'])
        self.cached=self.c['retained_reason'] if self.c['retained_magic']==0x5a5a5a5a else {1:0,2:1,3:2}.get(self.c['raw_reason'],8)
        return self.cached
    def poll(self,index):
        if self.polls>=len(self.c['polls']):raise ValueError('finite poll trace exhausted')
        i,value,status=self.c['polls'][self.polls];self.polls+=1
        if i!=index:raise ValueError('poll index differs from native policy')
        self.actions.append(f'key:{i}:{value}:{status}');return value,status
    def key(self):
        reason=self.reason();self.actions.append('log:reason')
        if reason in (3,6):return 0
        self.actions.append('power')
        if self.c['power_status'] or not self.c['power_present']:self.actions.append('log:no_power');return 0
        while True:
            value,status=self.poll(0)
            if status:return 0
            if value==0:break
            self.actions.append('delay:50')
        for _ in range(20):
            first,status=self.poll(0)
            if status:return 0
            second,status=self.poll(1)
            if status:return 0
            if first==1 and second==1:break
            self.actions.append('delay:50')
        else:return 0
        self.actions.append('log:press')
        for _ in range(20):
            first,status=self.poll(0)
            if status:return 0
            second,status=self.poll(1)
            if status:return 0
            if first==0 or second==0:return 0
            self.actions.append('delay:50')
        self.actions.append('log:key_pass');return 1
    def prefix(self):
        c=self.c;record=bytearray(298);key_result=0
        self.actions.extend(['log:build','boundary:flag:220','boundary:flag:221','boundary:flag:222','boundary:display',
                             'boundary:hw','boundary:board_init','log:hw','keyboard:register'])
        if c['register_status']==0:
            self.keyboard=c['handle'];self.actions.append('keyboard:init')
            if c['keyboard_init_status']:self.keyboard=0
        if self.keyboard:
            key_result=self.key()
            if key_result:
                self.actions.append('log:backup_request');record=upgrade_record();self.set(record,'upgrade');self.actions.append('commit:no_op')
        else:self.reason();self.actions.append('log:fallback_reason')
        self.stopped=dict(pc=STOP,sp=0x81001000-0x150,key_result=key_result,record_sha256=digest(record))
    def result(self):
        rows=[]
        for op in self.c['operations']:
            returned=None
            if op=='get':returned=self.get()
            elif op=='set':returned=self.set(bytes.fromhex(self.c['payload_hex']),delete=self.c['delete'])
            elif op=='commit':self.actions.append('commit:no_op');returned=0
            elif op=='reason':returned=self.reason()
            elif op=='key':returned=self.key()
            elif op=='prefix':self.prefix()
            else:raise ValueError('unknown boot environment operation')
            rows.append(dict(returned=returned,buffer_sha256=digest(self.buffer),length_output=self.length,
                descriptor_sha256=digest(self.descriptor),maintenance_flag=self.flag,reason_cache=self.cached,
                keyboard=self.keyboard,polls_consumed=self.polls,appends=list(self.appends),stopped=self.stopped))
        return dict(actions=self.actions,rows=rows)


def contract(c):
    if not 0<=c['capacity']<=1024 or len(bytes.fromhex(c['stored_hex']))>1024 or len(bytes.fromhex(c['payload_hex']))>512:raise ValueError('bounded environment sizes')
    if not 1<=len(c['key_name'])<=31 or not c['key_name'].isascii() or '\0' in c['key_name']:raise ValueError('bounded ASCII key')
    if len(c['polls'])>160 or any(i not in (0,1) or not 0<=v<=255 or not 0<=s<=0xffffffff for i,v,s in c['polls']):raise ValueError('bounded polling fixture')
    if 'prefix' in c['operations'] and c['operations']!=['prefix']:raise ValueError('stopped caller prefix is terminal')
    return Model(c).result()


def poll_trace(release=(0,),press=((1,1),),hold=None):
    if hold is None:hold=[(1,1)]*20
    return [[0,v,0] for v in release]+[[i,v,0] for pair in (*press,*hold) for i,v in enumerate(pair)]


def native_vectors():
    cases=[]
    def add(name,ops,**changes):
        c=dict(name=name,operations=ops,ready=True,found=True,key_name='upgrade',stored_hex=bytes(range(32)).hex(),payload_hex=bytes(range(16)).hex(),
               capacity=12,has_output=True,size_output=True,read_status=0,delete=False,reserve_result=0,append_status=0,
               remove_direct=0,remove_mark=0,remove_final=0,maintenance_required=0,maintenance_status=0,cached_reason=0xffffffff,
               raw_reason=1,retained_magic=0,retained_reason=0,power_status=0,power_present=True,polls=poll_trace(),
               handle=0x55,keyboard_initial=0,register_status=0,keyboard_init_status=0)|changes
        c['expected']=contract(c);cases.append(c)
    add('get_truncated',['get']);add('get_full',['get'],capacity=64);add('get_zero_capacity',['get'],capacity=0)
    add('get_missing',['get'],found=False);add('get_uninitialized',['get'],ready=False)
    add('get_null_output',['get'],has_output=False);add('get_null_size',['get'],size_output=False)
    add('get_null_both',['get'],has_output=False,size_output=False);add('get_read_failure',['get'],read_status=2)
    add('get_empty_value',['get'],stored_hex='')
    add('set_existing',['set']);add('set_new',['set'],found=False);add('set_delete',['set'],delete=True)
    add('set_uninitialized',['set'],ready=False);add('set_no_space',['set'],reserve_result=0xffffffff)
    add('set_new_append_failure',['set'],found=False,append_status=5);add('set_mark_failure',['set'],remove_mark=4)
    add('set_old_append_failure',['set'],append_status=5);add('set_final_failure',['set'],remove_final=3)
    add('set_delete_failure',['set'],delete=True,remove_direct=4)
    add('set_maintenance',['set'],maintenance_required=1,maintenance_status=7)
    add('set_mark_failure_maintenance',['set'],remove_mark=4,maintenance_required=1)
    add('set_no_space_maintenance',['set'],reserve_result=0xffffffff,maintenance_required=1)
    add('set_delete_maintenance',['set'],delete=True,maintenance_required=1)
    add('set_nonnull_empty',['set'],payload_hex='',found=False,key_name='k')
    add('commit_only',['commit']);add('set_then_commit',['set','commit'])
    for raw in (0,1,2,3,99):add('reason_raw_'+str(raw),['reason','reason'],raw_reason=raw)
    for cache in (0,6,8,0xfffffffe):add('reason_cached_'+str(cache),['reason'],cached_reason=cache)
    for retained in (3,6,0xffffffff):add('reason_retained_'+str(retained),['reason','reason'],retained_magic=0x5a5a5a5a,retained_reason=retained)
    add('key_success',['key'])
    for reason in (3,6):add('key_reason_'+str(reason),['key'],retained_magic=0x5a5a5a5a,retained_reason=reason)
    add('key_power_error',['key'],power_status=7);add('key_no_power',['key'],power_present=False)
    add('key_release_wait',['key'],polls=poll_trace(release=(2,3,0)))
    add('key_press_last',['key'],polls=poll_trace(press=[(0,0)]*19+[(1,1)]))
    add('key_press_timeout',['key'],polls=poll_trace(press=[(0,0)]*20,hold=[]))
    add('key_press_nonboolean',['key'],polls=poll_trace(press=[(2,1)]*20,hold=[]))
    add('key_hold_last_release',['key'],polls=poll_trace(hold=[(1,1)]*19+[(0,1)]))
    add('key_hold_second_release',['key'],polls=poll_trace(hold=[(1,0)]))
    add('key_hold_nonboolean',['key'],polls=poll_trace(hold=[(2,7)]*20))
    for at in (0,1,2,3,4):
        trace=poll_trace();trace[at][2]=5;add('key_driver_error_'+str(at),['key'],polls=trace)
    add('prefix_backup',['prefix'],found=False)
    add('prefix_env_uninitialized',['prefix'],ready=False,found=False)
    add('prefix_reserve_failure',['prefix'],reserve_result=0xffffffff)
    add('prefix_append_failure',['prefix'],found=False,append_status=5)
    add('prefix_register_failure',['prefix'],register_status=7)
    add('prefix_init_failure',['prefix'],keyboard_init_status=7)
    add('prefix_key_rejected',['prefix'],retained_magic=0x5a5a5a5a,retained_reason=3)
    add('prefix_stale_handle',['prefix'],keyboard_initial=0x77,register_status=7,found=False)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from model')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    if memory.string(0x80c32c30)!=BACKUP:raise ValueError('unexpected backup path')
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Storage lookup/read/reserve/append/remove/maintenance, locks, board/keyboard/power/delay/log services are supplied.',
            'Backend callback traces/data are checked; persistence, visibility, rollback, flash layout/atomicity and locking behavior are not modeled.',
            'Retained bytes are synthetic; actual reason cache/copy, polling policy and upgrade-record caller prefix execute.',
            'The prefix stops before dispatch at 80c005b8; no recovery UI, image launch, device I/O or physical gesture/time calibration.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect boot environment: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
