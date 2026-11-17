#!/usr/bin/env python3
"""Original NAND candidates and bounded identification/registration contracts.

IDs, power, bus transfers, feature operations and registration results are
supplied. Candidate descriptors are image evidence, not live chip identification.
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
TABLE_PATH=ROOT/'analysis/nand-chips.json'
TABLE=0x80c3dcd0
COPY=0x81300000
HEAP=0x81400000
MUTEX=0x81240000
REGULATOR=0x81250000
CONFIG=dict(probe=0x80c2874a,wrapper=0x80c27aac,register=0x80c27524,match=0x80c28318,compat=0x80c29d4c,
    read_id=0x80c2819e,reset=0x80c281fc,property=0x80c1d13a,regulator=0x80c1dee4,
    disable=0x80c1e046,enable=0x80c1df76,delay=0x80c164aa,
    bus_init=0x80c10580,transfer=0x80c106f0,workaround=0x80c29f5c,uid=0x80c28422,
    set_feature=0x80c27d48,get_feature=0x80c27ce8,bbt=0x80c2785a,create_mutex=0x80c16afa,
    alloc=0x80c1a308,memset=0x80c2e014,object_register=0x80c2cecc,compare=0x80c2e5e8,
    logger=0x80c1cd7a,assertion=0x80c16516,pack=0x80c026a6,extract=0x80c025d4)
RANGES=((0x80c2874a,0x314),(0x80c27aac,0x46),(0x80c27524,0x80),
    (0x80c28318,0x56),(0x80c2819e,0x5e),(0x80c281fc,0x5e),(0x80c29d4c,0x48),
    (0x80c026a6,0xe4),(0x80c025d4,0xd2))
TARGETS=tuple(CONFIG[k] for k in ('probe','wrapper','register','match','read_id','reset','compat','pack','extract'))
LOGS={0x80c3d704:'regulator_missing',0x80c3d744:'no_chip_match',0x80c3d770:'chip_summary',
    0x80c3d79c:'feature_write_error',0x80c3d7cc:'feature_read_error',0x80c3d7e8:'feature_mismatch',
    0x80c3d81c:'boot_guard',0x80c3d850:'probe_error'}


def chip_table(memory):
    rows=[]
    for pointer in struct.unpack('<11I',memory.read(TABLE,44)):
        raw=memory.read(pointer,0xb8);word=lambda off:struct.unpack_from('<I',raw,off)[0]
        feature_pointer=word(0x88);feature_count=raw[0x8c]
        if not 1<=feature_count<=8:raise ValueError('feature count')
        features=memory.read(feature_pointer,feature_count*2)
        rows.append(dict(address=pointer,name=memory.string(word(0x38)),name_pointer=word(0x38),sha256=digest(raw),
            id=list(raw[0x2c:0x31]),reset_delay_us=word(8),capacity_word=word(0x3c),blocks=word(0x48),
            pages=word(0x54),pages_per_block=word(0x58),page_size=word(0x5c),spare=word(0x60),
            feature_pointer=feature_pointer,features=[list(features[i:i+2]) for i in range(0,len(features),2)],
            uid=bool(raw[0xa6]),ecc_total=struct.unpack_from('<H',raw,0x9a)[0],
            ecc_unit=struct.unpack_from('<H',raw,0x9c)[0],positions=list(struct.unpack_from('<4H',raw,0x9e))))
    return dict(boot_sha256=BOOT_HASH,table_address=TABLE,table_sha256=digest(memory.read(TABLE,44)),
        chips=rows,bus_property=0x80d81b00,bus_operations=struct.unpack('<I',memory.read(0x80d81b00,4))[0],
        bus_callbacks=list(struct.unpack('<4I',memory.read(0x80d809a8,16))),
        driver_property=0x80d81b28,driver_operations=struct.unpack('<I',memory.read(0x80d81b28,4))[0],
        driver_callbacks=list(struct.unpack('<7I',memory.read(0x80d811f4,28))),hardware_execution=False)


def facts():return json.loads(TABLE_PATH.read_bytes())


def match(expected,received):
    if expected[0]!=received[0]:return -1
    if expected[1]!=received[1]:return -2
    if expected[2] and expected[2]!=received[2]:return -3
    if expected[3] and expected[3]!=received[3]:return -4
    if expected[4] and expected[4]!=received[3]:return -5
    return 0


class Stop(Exception):
    def __init__(self,owner,line):self.info=dict(kind='assertion',owner=owner,line=line)


class Model:
    def __init__(self,c):
        self.c=c;self.table=facts()['chips'];self.actions=[];self.selected=0;self.bus_calls=0;self.reads=0
        self.mutex=MUTEX if c['mutex_present'] else 0;self.root=0;self.regulator=0;self.guard_pages=0;self.guard_blocks=0
        self.heap=None;self.features={};self.feature_reads=0;self.feature_writes=0
    def log(self,tag):self.actions.append('log:'+tag)
    def probe(self):
        c=self.c;self.regulator=REGULATOR if c['regulator_present'] else 0
        self.actions.append('regulator:'+str(int(c['regulator_present'])))
        if self.regulator:
            self.actions.extend((f'disable:{c["power_status"]}','delay:20',f'enable:{c["power_status"]}','delay:20'))
        else:self.log('regulator_missing')
        self.selected=0
        for _ in range(3):
            for i,chip in enumerate(self.table):
                self.bus_calls+=1;status=-9 if self.bus_calls==c['bus_fail_at'] else 0
                self.actions.append(f'bus_init:{i}:{status}')
                if status:raise Stop(0x80c3dc70,0x57)
                if c['inject_read_error']:
                    self.actions.append('injected_read_error');self.log('probe_error');return 0xffffffce
                received=[255]*5 if self.reads<c['delayed_pass']*11 else c['read_id']
                self.reads+=1;status=-9 if self.reads==c['read_fail_at'] else 0
                self.actions.append(f'read_id:{i}:{bytes(received).hex()}:{status}')
                if status:raise Stop(0x80c3d4e8,0x17f)
                if match(chip['id'],received)==0:self.selected=chip['address'];break
            if self.selected:break
        if not self.selected:self.log('no_chip_match');self.log('probe_error');return 0xfffffffc
        chip=next(row for row in self.table if row['address']==self.selected)
        if c['inject_reset_error']:
            self.actions.append('injected_reset_error');self.log('probe_error');return 0xffffffcd
        self.actions.append('reset:'+str(c['reset_status']))
        if c['reset_status']:raise Stop(0x80c3d4d8,0x192)
        self.actions.append('delay:'+str(chip['reset_delay_us']//1000+1))
        self.actions.append('workaround:'+str(c['workaround_status']));self.log('chip_summary')
        if chip['uid']:self.actions.append('uid:'+str(c['uid_status']))
        for register,value in chip['features']:
            self.feature_writes+=1;status=-9 if self.feature_writes==c['feature_write_fail_at'] else 0
            self.actions.append(f'set_feature:{register}:{value}:{status}')
            if status:self.log('feature_write_error');self.log('probe_error');return 0xfffffffb
            self.features[register]=value;self.feature_reads+=1
            status=-9 if self.feature_reads==c['feature_read_fail_at'] else 0
            read=value^1 if self.feature_reads==c['feature_mismatch_at'] else value
            self.actions.append(f'get_feature:{register}:{read}:{status}')
            if status:self.log('feature_read_error');self.log('probe_error');return 0xfffffffa
            if read!=value:self.log('feature_mismatch');self.log('probe_error');return 0xfffffff9
        self.actions.append(f'bbt:{chip["blocks"]}:{chip["page_size"]}:{chip["pages_per_block"]}:{c["bbt_status"]}')
        self.guard_pages=0x100000//chip['page_size'];self.guard_blocks=self.guard_pages//chip['pages_per_block'];self.log('boot_guard')
        return 0
    def wrapper(self):
        result=self.probe()
        if not result and not self.mutex:
            self.actions.append('mutex:create:'+str(int(not self.c['mutex_fail'])))
            if self.c['mutex_fail']:raise Stop(0x80c3d434,0x1e)
            self.mutex=MUTEX
        return result
    def run(self):
        c=self.c;stopped=None;layout_hash=None;layout_record=None
        try:
            if c['mode']=='match':result=match(c['expected_id'] or self.table[c['chip_index']]['id'],c['read_id'])&0xffffffff
            elif c['mode']=='compat':
                if c['compat_absent']:result=0xffffffff
                else:
                    self.selected=self.table[c['chip_index']]['address'];name=self.table[c['chip_index']]['name']
                    result=0 if name.startswith(('Winbond W25N02LWZEIG','Winbond W25N04LWZEIG')) else 0xffffffff
            elif c['mode']=='probe':result=self.probe()
            elif c['mode']=='layout':
                result=self.probe()
                if result==0:
                    chip=next(row for row in self.table if row['address']==self.selected)
                    if chip['ecc_unit']<4 or chip['positions'][1]+4>chip['spare']:raise ValueError('original contiguous layout')
                    data=bytearray(b'\xff'*chip['spare']);at=chip['positions'][1];data[at:at+4]=bytes.fromhex('01004546')
                    self.actions.append('spare_fill:'+str(chip['spare']));layout_hash=digest(data);layout_record='01004546'
            elif c['mode']=='wrapper':result=self.wrapper()
            elif c['mode']=='register':
                self.actions.append('property:dev_nand:'+str(int(c['property_present'])))
                self.root=0x80d81b28 if c['property_present'] else 0
                if not self.root:raise Stop(0x80c3d208,0x31)
                if c['driver_state']!='ok':result=0xfffffffa
                else:
                    result=self.wrapper()
                    if result:result=0xfffffffa
                    else:
                        pointer=0 if c['alloc_fail'] else HEAP;self.actions.append('alloc:60:'+str(pointer))
                        if not pointer:result=0xfffffffa
                        else:
                            self.heap=bytearray(60);self.actions.append('fill_object:60');struct.pack_into('<I',self.heap,40,0x80d811d8)
                            self.actions.append('object_register:dev_nand:23:'+str(c['register_status']));result=c['register_status']&0xffffffff
            else:raise ValueError('probe mode')
        except Stop as stop:result=None;stopped=stop.info
        return dict(actions=self.actions,rows=[dict(returned=result,stopped=stopped,selected=self.selected,root=self.root,mutex=self.mutex,
            regulator=self.regulator,guard_pages=self.guard_pages,guard_blocks=self.guard_blocks,
            heap_sha256=digest(self.heap) if self.heap is not None else None,heap_active=self.heap is not None,
            layout_sha256=layout_hash,layout_record=layout_record)])


def contract(c):
    if len(c['read_id'])!=5 or any(not 0<=v<=255 for v in c['read_id']) or not 0<=c['delayed_pass']<=2:raise ValueError('probe ID bounds')
    if c['expected_id'] is not None and len(c['expected_id'])!=5:raise ValueError('five expected bytes')
    return Model(c).run()


def native_vectors():
    cases=[];chips=facts()['chips']
    def add(name,mode='probe',**changes):
        c=dict(name=name,mode=mode,chip_index=3,read_id=chips[3]['id'],expected_id=None,delayed_pass=0,
            regulator_present=True,power_status=0,bus_fail_at=0,read_fail_at=0,reset_status=0,
            inject_read_error=False,inject_reset_error=False,workaround_status=0,uid_status=0,bbt_status=0,
            feature_write_fail_at=0,feature_read_fail_at=0,feature_mismatch_at=0,
            mutex_present=False,mutex_fail=False,property_present=True,driver_state='ok',alloc_fail=False,register_status=0,compat_absent=False)|changes
        c['expected']=contract(c);cases.append(c)
    for i,chip in enumerate(chips):add(f'probe_candidate_{i}',chip_index=i,read_id=chip['id'])
    for i,chip in enumerate(chips):add(f'layout_candidate_{i}','layout',chip_index=i,read_id=chip['id'])
    add('probe_no_match',read_id=[255]*5);add('probe_second_round',delayed_pass=1);add('probe_third_round',delayed_pass=2)
    add('probe_no_regulator',regulator_present=False);add('probe_power_status_ignored',power_status=-9)
    add('probe_bus_error',bus_fail_at=1);add('probe_id_transfer_assert',read_fail_at=1)
    add('probe_reset_transfer_assert',reset_status=-9);add('probe_injected_read_error',inject_read_error=True)
    add('probe_injected_reset_error',inject_reset_error=True)
    add('probe_feature_write_error',feature_write_fail_at=2);add('probe_feature_read_error',feature_read_fail_at=1)
    add('probe_feature_mismatch',feature_mismatch_at=2)
    add('probe_workaround_status_ignored',workaround_status=-9);add('probe_uid_status_ignored',uid_status=-9)
    add('probe_bbt_status_ignored',bbt_status=-9)
    add('wrapper_success','wrapper');add('wrapper_existing_mutex','wrapper',mutex_present=True)
    add('wrapper_mutex_assert','wrapper',mutex_fail=True);add('wrapper_probe_error','wrapper',read_id=[255]*5)
    add('register_success','register');add('register_missing_property','register',property_present=False)
    add('register_missing_operations','register',driver_state='ops_missing')
    add('register_missing_init','register',driver_state='callback_missing')
    add('register_alloc_error','register',alloc_fail=True);add('register_object_error','register',register_status=-11)
    add('register_probe_error','register',read_id=[255]*5)
    base=[0xef,0xba,0x21,0,0]
    add('match_manufacturer','match',expected_id=base,read_id=[0,0xba,0x21,0,0])
    add('match_device','match',expected_id=base,read_id=[0xef,0,0x21,0,0])
    add('match_third','match',expected_id=base,read_id=[0xef,0xba,0x22,0,0])
    add('match_fourth','match',expected_id=[0xef,0xba,0x21,0x12,0],read_id=[0xef,0xba,0x21,0x13,0])
    add('match_fifth_field','match',expected_id=[0xef,0xba,0x21,0x12,0x34],read_id=[0xef,0xba,0x21,0x12,0x34])
    add('match_fifth_uses_fourth_byte','match',expected_id=[0xef,0xba,0x21,0x12,0x12],read_id=[0xef,0xba,0x21,0x12,0x34])
    add('match_optional_zero','match',expected_id=[0xe5,0x21,0,0,0],read_id=[0xe5,0x21,0xaa,0xbb,0xcc])
    add('match_received_fifth_ignored','match',expected_id=base,read_id=[0xef,0xba,0x21,0,0xcc])
    add('compat_allowed','compat');add('compat_rejected','compat',chip_index=0);add('compat_absent','compat',compat_absent=True)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=image_memory(archive)
    if chip_table(memory)!=facts():raise ValueError('chip table differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=BOOT_HASH,chip_table_sha256=digest(TABLE_PATH.read_bytes()),vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original eleven chip descriptors, candidate order, ID/reset command builders, probe, mutex wrapper and driver root setup execute with supplied bus/power/feature/BBT services.',
            'Candidate IDs and all results are authored; supported geometry is image evidence, not proof of the fitted NAND chip or electrical operation.',
            'Device-object registration and heap are supplied. Explicit read/reset-helper errors are injections; transport errors stop at assertions before their bodies.',
            'The fifth-ID-field counterexample uses an authored descriptor copy; all original fifth fields are zero. Physical ID reads/probing, feature behavior, ECC/bus and boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('table-output','vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.table_output:
            with zipfile.ZipFile(a.archive) as z:r=chip_table(image_memory(z))
            a.table_output.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');return
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND probe: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
