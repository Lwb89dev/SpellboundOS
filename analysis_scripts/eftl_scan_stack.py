#!/usr/bin/env python3
"""Original EFTL map scan and NAND bad-marker/OOB reads through QSPI."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import eftl_repair_stack as repair
else:
    import eftl_repair_stack as repair

qspi=repair.qspi
EXTRA_RANGES=((0x80c01d8a,352),(0x80c028d8,52),(0x80c29042,228))
RANGES=repair.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)


def oob(logical=0,variant='valid',unit=4):
    b=bytearray(b'\xff'*64);tag=68 if variant=='bad_tag' else 69
    record=struct.pack('<H',logical)+bytes([tag,(logical%256+logical//256+tag)&255])
    if variant=='bad_crc':record=record[:3]+bytes([record[3]^1])
    if variant=='empty':record=b'\xff'*4
    if unit==4:b[20:24]=record
    else:b[4:6]=record[:2];b[20:22]=record[2:]
    return bytes(b)


class Model(repair.Model):
    def __init__(self,c):
        super().__init__(c);self.counters=list(c['scan_counters']);self.marker=c['scan_marker']
    def bad_marker(self,block,blocking):
        for i in range(3):
            saved=self.buffer;self.buffer=bytearray(512)
            result=self.page_read(block*64+i,2048,2,blocking);data=bytes(self.buffer[:2]);self.buffer=saved
            if self.stopped:return None
            if result:
                self.actions.append('log:bad_mark_error');return result
            if data[0]&data[1]!=255:
                self.actions.append('log:bad_mark_found');return 103
        return 0
    def chip_query(self,query,arg):
        if query!=10:return super().chip_query(query,arg)
        self.actions.append('chip_ioctl:10')
        return self.bad_marker(struct.unpack_from('<I',arg)[0],True if self.c['fast'] else self.current_direct)
    def scan(self):
        c=self.c
        for i in range(c['scan_count']):
            self.flags[i]|=254
            if c['fast']:result=self.chip_query(10,bytearray(struct.pack('<I',i+c['fast_base']//64)))
            else:result=self.partition_ioctl(10,bytearray(struct.pack('<I',i)))
            if self.stopped:return None
            if result:
                self.actions.append('log:scan_bad_block')
                if result<0 or c['scan_repair']:
                    result=self.erase_block(i)
                    if self.stopped:return None
            if result:
                self.flags[i]|=1;self.counters[2]=(self.counters[2]+1)&65535;continue
            result,record=self.readback(i*64)
            if self.stopped:return None
            if result:self.actions.append('log:scan_oob_error');return -1
            if self.check_metadata(record):
                logical=struct.unpack_from('<H',record)[0]
                if logical>=8:raise ValueError('scan mapping backing')
                if self.mapping[logical]==65535:
                    self.mapping[logical]=i;self.counters[1]=(self.counters[1]+1)&65535;self.flags[i]=(self.flags[i]&1)|128
            else:self.counters[0]=(self.counters[0]+1)&65535
        result=0 if c['scan_repair'] or self.counters[0] or not self.counters[2] else 1
        if not result:self.marker=165
        return result
    def storage_mutation(self):return self.scan()
    def run(self):
        result=super().run();row=result['rows'][0];ctx=bytearray.fromhex(row['eftl_context_hex'])
        ctx[4]=self.marker;struct.pack_into('<I',ctx,16,self.c['scan_count']);struct.pack_into('<3H',ctx,56,*self.counters)
        row['eftl_context_hex']=ctx.hex();return result


def contract(c):
    if not c['native_scan'] or c['repair_entry'] or c['write_readback']:raise ValueError('scan entry')
    if not 0<=c['scan_count']<=8 or c['scan_repair'] not in (0,1) or not 0<=c['scan_marker']<=255:raise ValueError('scan bounds')
    if len(c['scan_counters'])!=3 or any(not 0<=v<=65535 for v in c['scan_counters']):raise ValueError('scan counters')
    if not 1<=len(c['cache_payloads'])<=32 or any(len(bytes.fromhex(v)) not in (2,64) for v in c['cache_payloads']):raise ValueError('marker/OOB backing')
    if not c['responses'] or len(c['responses'])>64 or any(v not in (0,4,32) for v in c['responses']):raise ValueError('scan statuses')
    if c['ecc_unit'] not in (2,4) or c['ecc_total']!=16 or c['positions']!=[4,20,36,52]:raise ValueError('scan geometry')
    repair.contract(c|dict(native_scan=False,mapping=[3]+[65535]*7,write_flags=[1]*8,
        responses=[0],cache_payloads=[oob().hex()],ecc_unit=4))
    return Model(c).run()


def native_vectors():
    base=repair.native_vectors()['cases'][0];cases=[]
    def payload(logical=0,variant='valid',marker_at=None,marker=b'\x00\x00',unit=4):
        marks=[b'\xff\xff']*3
        if marker_at is not None:marks[marker_at]=marker;return marks[:marker_at+1]
        return marks+[oob(logical,variant,unit)]
    def add(name,blocks=None,payloads=None,**changes):
        blocks=blocks or [payload(2),payload(0)]
        c=base|dict(name=name,native_scan=True,scan_count=len(blocks),scan_repair=0,scan_marker=0,scan_counters=[0,0,0],
            mapping=[65535]*8,write_flags=[0]*8,responses=[0],write_readback=False)|changes
        c['cache_payloads']=[b.hex() for b in (payloads or [v for block in blocks for v in block])]
        c['expected']=contract(c);cases.append(c)
    add('scan_connected')
    add('scan_mixed',blocks=[payload(2),payload(0,'empty'),payload(0),payload(marker_at=0)])
    add('scan_duplicate_old_first',blocks=[payload(0),payload(0)])
    add('scan_retired_old_skipped',blocks=[payload(marker_at=0),payload(0)])
    add('scan_marker_second_page',blocks=[payload(marker_at=1)])
    add('scan_marker_third_page',blocks=[payload(marker_at=2)])
    add('scan_marker_second_byte',blocks=[payload(marker_at=0,marker=b'\xff\xfe')])
    add('scan_repair_marked_block',blocks=[payload()],scan_repair=1,payloads=[b'\x00\x00',oob()])
    add('scan_marker_io_erased',blocks=[payload()],responses=[32,0],payloads=[b'\xff\xff',oob()])
    add('scan_marker_io_erase_failed',blocks=[payload()],responses=[32,4,0],payloads=[b'\xff\xff'])
    add('scan_repair_erase_failed',blocks=[payload()],scan_repair=1,responses=[0,4,0],payloads=[b'\x00\x00'])
    add('scan_first_oob_io_error',blocks=[payload()],responses=[0,0,0,32,0])
    add('scan_later_oob_io_error',responses=[0]*7+[32,0])
    add('scan_bad_tag',blocks=[payload(0,'bad_tag')])
    add('scan_bad_crc',blocks=[payload(0,'bad_crc')])
    add('scan_generic_stale',fast=False)
    add('scan_irq_direct',fast=False,irq_context=1)
    add('scan_segmented_oob',blocks=[payload(2,unit=2)],ecc_unit=2)
    add('scan_logical_beyond_count',blocks=[payload(7)])
    add('scan_existing_map',blocks=[payload(0)],mapping=[7]+[65535]*7)
    add('scan_empty',scan_count=0)
    actions=cases[0]['expected']['actions'];cache=[i for i,a in enumerate(actions) if a.startswith('w:12:4:') and int(a.split(':')[-1])>>24==0x6b][3]
    before=actions[:cache];ready=sum(a.startswith('r:24:4:') for a in before);ticks=sum(a.startswith('tick:') for a in before)
    add('scan_oob_bus_assertion',ready=[3]*ready+[0],ticks=[0]*(ticks+1)+[1001])
    return dict(schema=1,bound_per_case=repair.read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=repair.read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=repair.read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in repair.mutation.storage.DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original EFTL scan/bad-block adapter/NAND three-page bad-marker check/OOB/erase connect through partition/context/mutex/BBT/QSPI/FIFO and selected DMA control.',
            'Cache marker/OOB bytes, statuses, ready backing/counters and peripheral/RTOS/cache/copy leaf services are authored; no physical NAND persistence or DMA movement is modeled.',
            'Duplicate selection and error cleanup are selected RAM/command observations; full initialization, persistent reboot reconstruction, BBT provenance, concurrency and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect connected EFTL scan: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
