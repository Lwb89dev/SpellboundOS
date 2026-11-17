#!/usr/bin/env python3
"""Original NAND erase/copy/OOB policy connected to BBT, bus and QSPI."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_program_stack as program
else:
    import nand_program_stack as program

read=program.read
qspi=program.qspi
EXTRA_RANGES=((0x80c291e6,264),(0x80c28d7a,330),(0x80c28ec4,382),
    (0x80c28136,104),(0x80c286b2,152),(0x80c2800a,98))
RANGES=program.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)


class Model(program.Model):
    def map(self,value,block=False):
        self.actions.append(('native_remap_block:' if block else 'native_remap_page:')+str(value))
        state=bytes.fromhex(self.c['bbt_hex']);magic,count=struct.unpack_from('<II',state)
        if magic!=read.bbt.MAGIC:return value
        mapped=value if block else value//64
        if not block:self.actions.append('native_remap_block:'+str(mapped))
        for bad in struct.unpack_from('<'+'H'*count,state,12):
            if bad>mapped:break
            mapped=(mapped+1)&0xffffffff
        if mapped>=struct.unpack_from('<I',state,160)[0]:return None
        return mapped if block else (value%64+64*mapped)&0xffffffff
    def poll(self,limit,sleep=False):
        for i in range(limit):
            self.actions.append('sleep:1' if sleep else 'delay:5')
            failed,response=self.bus(0x0f,192,1,1,write=False,status=True)
            if failed:return None
            if i+1==limit:self.actions.append('log:busy_timeout');return 255
            if not response&1:return response
        raise ValueError('empty poll fixture')
    def policy(self):
        c=self.c;erase=c['operation']=='erase'
        if not c['chip']:return -2
        source=self.map(c['block'] if erase else c['page'],erase)
        if source is None:return -151 if erase else -150
        dest=None if erase else self.map(c['dest'])
        if not erase and dest is None:return -150
        if erase:
            if source>=1024:return -1
        elif source>=65536 or dest>=65536 or c['operation']=='copy_oob' and c['count']>64:return -1
        if c['guard'] and (source<(8 if erase else 512) or not erase and dest<512):
            self.actions.append('log:block_guard' if erase else 'log:page_guard');return -250
        if erase:
            if self.bus(0x06)[0] or self.bus(0xd8,source*64,3)[0]:return None
            status=self.poll(4000 if c['blocking'] else 20,not c['blocking'])
            return None if status is None else (-104 if status&4 else 0)
        if self.bus(0x13,source,3)[0]:return None
        status=self.poll(2000)
        if status is None:return None
        if status&0x30==0x20:return -101
        if self.bus(0x06)[0]:return None
        if c['operation']=='copy_oob':
            column=2048|(0x1000 if c['plane'] and source&64 else 0)
            if self.bus(0x34,column,2,c['count'],0,3)[0]:return None
        if self.bus(0x10,dest,3)[0]:return None
        status=self.poll(2000)
        return None if status is None else (-102 if status&8 else 0)
    def run(self):
        c=self.c
        if not c['defer_reinit']:self.initialize();self.initialized=True
        value=self.policy()
        if value and self.stopped is None:self.actions.append('log:erase_result' if c['operation']=='erase' else 'log:copy_result')
        result=self.snapshot(None if self.stopped else value&0xffffffff);row=result['rows'][0]
        row.update(rx_bytes=self.rx,tx_hex=self.tx.hex(),board_mmio={str(k):v for k,v in sorted(self.pins.regs.items())},
            reinit_flag=int(c['defer_reinit'] and not self.initialized),feature_reads=self.feature_reads)
        return result


def contract(c):
    if c['operation'] not in ('erase','copy_page','copy_oob') or c['mode']!='platform_'+c['operation']:raise ValueError('maintenance entry')
    if not all(c[k] for k in ('native_page','native_program','native_maintenance','full_platform','native_dma','buffer')):raise ValueError('connected backing')
    state=bytes.fromhex(c['bbt_hex'])
    if len(state)!=164 or struct.unpack_from('<I',state,4)[0]>64 or struct.unpack_from('<I',state,148)[0]!=64:raise ValueError('bounded BBT')
    if not 0<=c['count']<=65 or c['alignment'] or any(not 0<=c[k]<=0xffffffff for k in ('page','dest','block')):raise ValueError('bounded maintenance')
    if not c['responses'] or len(c['responses'])>4000 or any(not 0<=v<=255 for v in c['responses']):raise ValueError('bounded status input')
    return Model(c).run()


def native_vectors():
    base=program.native_vectors()['cases'][0];cases=[]
    def add(name,operation='erase',active=True,bad=None,**changes):
        state=read.bbt.initial(dict(active=active,bad=[1,3,7] if bad is None else bad,blocks=1024,page_size=2048,ppb=64,reserve=16,primary=1023,backup=1022))
        c=base|dict(name=name,mode='platform_'+operation,operation=operation,native_maintenance=True,
            bbt_hex=state.hex(),page=600,dest=700,block=12,count=64,blocking=True,responses=[0])|changes
        c['expected']=contract(c);cases.append(c)
    for operation in ('erase','copy_page','copy_oob'):
        add(operation+'_ready',operation);add(operation+'_inactive_bbt',operation,active=False)
        add(operation+'_deferred_init',operation,defer_reinit=True)
        add(operation+'_missing_chip',operation,chip=False)
        add(operation+'_reserved_source',operation,block=1019,page=65216)
        add(operation+'_out_of_range',operation,active=False,block=1024,page=65536)
        add(operation+'_guarded_source',operation,block=4,page=319)
        add(operation+'_guard_boundary',operation,block=5,page=320)
        add(operation+'_guard_disabled',operation,block=0,page=0,guard=False)
        add(operation+'_busy_then_ready',operation,responses=[1,1,0])
    add('erase_sleep_ready',blocking=False);add('erase_failed_status',responses=[4])
    add('erase_program_bit_ignored',responses=[8]);add('erase_sleep_timeout',blocking=False,responses=[1])
    add('erase_sleep_ready_at_limit',blocking=False,responses=[1]*19+[0])
    add('erase_delay_timeout',responses=[1]);add('erase_delay_ready_at_limit',responses=[1]*3999+[0])
    add('erase_enable_assertion',done=[0],ticks=[0,1001])
    add('erase_command_assertion',done=[1,0],ticks=[0,0,1001])
    add('erase_status_assertion',ready=[0],ticks=[0,0,0,1001])
    for operation in ('copy_page','copy_oob'):
        add(operation+'_reserved_dest',operation,dest=65216)
        add(operation+'_dest_out_of_range',operation,active=False,dest=65536)
        add(operation+'_guarded_dest',operation,dest=319)
        add(operation+'_ecc_bad',operation,responses=[0x20])
        add(operation+'_program_failed',operation,responses=[0,8])
        add(operation+'_load_assertion',operation,done=[0],ticks=[0,1001])
        add(operation+'_status_assertion',operation,ready=[0],ticks=[0,0,1001])
    add('copy_source_timeout_then_success','copy_page',responses=[1]*2000+[0])
    add('copy_program_timeout','copy_page',responses=[0]+[1]*2000)
    add('copy_both_timeouts','copy_page',responses=[1])
    add('copy_same_source_dest','copy_page',dest=600)
    add('copy_oob_word_tail','copy_oob',count=13);add('copy_oob_zero_length','copy_oob',count=0)
    add('copy_oob_too_long','copy_oob',count=65)
    add('copy_oob_source_plane','copy_oob',plane=True,page=536)
    add('copy_oob_dest_plane_only','copy_oob',plane=True,dest=536)
    add('copy_oob_fifo_assertion','copy_oob',ready=[3,0],ticks=[0,0,0,0,0,1001])
    return dict(schema=1,bound_per_case=read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(read.platform.PIN_FACTS.read_bytes())!=read.platform.pin_facts(memory):raise ValueError('pin records differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['bound_per_case']!=read.BOUND or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in read.DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual erase, page copy and copy-with-OOB connect immutable BBT mapping, original builders, busy loops, platform, bus and QSPI FIFO.',
            'BBT/guard/plane variants, status FIFO, peripherals, timestamps and leaf delay/sleep/cache services are authored.',
            'Copy-with-OOB executes opcode 0x34 through the forced-direct FIFO path; no page cache, NAND cells or physical data movement are simulated.',
            'Physical erase/copy/OOB integrity, chip geometry/BBT/ECC, coherency, persistence, restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND maintenance: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
