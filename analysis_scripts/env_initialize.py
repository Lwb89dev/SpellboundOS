#!/usr/bin/env python3
"""Environment initialization, readiness binding and backup/dump orchestration.

All storage and heap services are synthetic. This does not boot a device or
establish physical backup, atomic rewrite, startup mapping or persistence.
"""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from .env_gc import Model as GCModel, native_vectors as gc_vectors, CONFIG as GC_CONFIG, RANGES as GC_RANGES
    from .env_scan import sector
    from .env_records import word, put
    from .recovery_validator import BOOT_HASH,digest,image_memory,table
else:
    from env_gc import Model as GCModel, native_vectors as gc_vectors, CONFIG as GC_CONFIG, RANGES as GC_RANGES
    from env_scan import sector
    from env_records import word,put
    from recovery_validator import BOOT_HASH,digest,image_memory,table

TABLE=0x81340000
CONFIG=GC_CONFIG|dict(initialize=0x80c0d58e,bind=0x80c0d67a,copy=0x80c0bd10,dump=0x80c0bc28,
    rewrite_service=0x80c24652,alloc=0x80c1a308,free=0x80c1a312)
RANGES=GC_RANGES+((0x80c0bc28,0x1ec),(0x80c0cd56,0x2c),(0x80c0d58e,0x1a8))
TARGETS=(0x80c0d58e,0x80c0d242,0x80c0cd56,0x80c0d0f4,0x80c0bc28,0x80c0bd10,0x80c0d67a)


class Model(GCModel):
    def __init__(self,c):
        super().__init__(c);backup_case=c|dict(sectors=c['backup_sectors'],records=c['backup_records'],source_cache=False,warm_cache=[])
        self.backup=bytearray(GCModel(backup_case).flash);self.heap=None;self.copy_reads=self.copy_writes=self.dump_reads=0
        self.duplicate=c['duplicate_guard'];self.ready=c['ready'];self.bound_pointer=c['prior_pointer'];self.bound_count=c['prior_count'];self.bound_base=c['prior_base']
        if c['stale_cache']:self.index[:]=b'\xa5'*128;self.ends[:]=b'\xa5'*32
    def read(self,at,n):
        if at>=0 and at+n<=0x4000:return super().read(at,n)
        if not 0<=at<0x4000 or at+n>0x4020:raise ValueError('bounded adjacent read backing')
        self.actions.append(f'read:{at}:{n}');return bytes(self.flash[at:])+b'\xff'*(at+n-0x4000)
    def allocate(self):
        ok=not self.c['fail_alloc'];self.actions.append('alloc:4096:'+str(int(ok)))
        if ok:
            if self.heap is not None:raise ValueError('allocation overlap')
            self.heap=bytearray(b'\xa5'*4096)
        return ok
    def release(self):
        if self.heap is None:raise ValueError('free without allocation')
        self.heap=None;self.actions.append('free:4096')
    def copy_backup(self):
        if not self.c['backup_handle'] or not self.c['active_handle'] or not self.allocate():return 7
        for at in range(0,0x4000,4096):
            self.copy_reads+=1;result=-1 if self.copy_reads==self.c['copy_read_error'] else (64 if self.copy_reads==self.c['copy_short_read'] else 4096)
            self.actions.append(f'backup_read:{at}:4096:{result}')
            if result<0:self.actions.append('log:copy_read_error');self.release();return 2
            self.heap[:result]=self.backup[at:at+result]
            self.copy_writes+=1;status=-1 if self.copy_writes==self.c['copy_write_error'] else 0
            self.actions.append(f'rewrite:{at}:4096:{status}:{digest(self.heap)}')
            if status<0:self.actions.append('log:copy_write_error');self.release();return 3
            self.flash[at:at+4096]=self.heap
        self.release();self.actions.append('log:copy_complete');return 0
    def dump_storage(self):
        if not self.c['active_handle'] or not self.allocate():return 7
        for at in range(0,0x4000,4096):
            self.dump_reads+=1;result=-1 if self.dump_reads==self.c['dump_read_error'] else 4096
            self.actions.append(f'dump_read:{at}:4096:{result}')
            if result<0:self.actions.append('log:dump_read_error');self.release();return 2
            self.heap[:]=self.flash[at:at+4096]
            self.actions.extend(['dump:row']*64)
        self.release();return 0
    def next_record(self,at):
        previous=word(self.desc,48)
        if previous!=0xffffffff:
            start=previous+(word(self.desc,8) if self.desc[1] else 1)
            if self.cached_end(start&~0xfff)==start:return 0xffffffff
        return super().next_record(at)
    def move_record(self,descriptor):
        saved=self.c;self.c=self.c|dict(duplicate_guard=self.duplicate)
        try:return super().move_record(descriptor)
        finally:self.c=saved
    def repair_scan(self):
        self.desc=bytearray(56)
        for context,status in self.contexts():
            if status or context[1] not in (2,3):continue
            at=word(context,4);put(self.desc,48,0xffffffff)
            for _ in range(8):
                address=self.next_record(at);put(self.desc,48,address)
                if address==0xffffffff:break
                self.decode(address);descriptor=bytearray(self.desc)
                if descriptor[1] and descriptor[0]==3:
                    self.actions.append('warn:marked_record');result=self.move_record(descriptor);self.desc=descriptor
                    self.actions.append('diagnostic:86e' if result==0 else 'diagnostic:872')
                    if result:return
                elif descriptor[0]==1:
                    self.status_write(address,5);return
            else:raise ValueError('bounded repair record count')
    def initialize(self):
        retry_copy=True;saved_result=0
        for _ in range(3):
            invalid=0;self.duplicate=True
            for context,_ in self.contexts():
                if not context[0]:
                    self.actions.append('warn:invalid_sector');invalid+=1;self.format_sector(word(context,4))
            if invalid:
                if retry_copy:
                    saved_result=self.copy_backup()
                    if saved_result==0:retry_copy=False;continue
                self.actions.append('warn:restore_defaults');retry_copy=False;self.restore_defaults()
            for context,_ in self.contexts():
                if context[0] and context[2]==3:self.flag=1;self.maintenance()
            for _ in range(3):
                self.repair_scan()
                if not self.flag:self.duplicate=False;return saved_result
                self.maintenance()
            self.dump_storage();self.copy_backup()
        raise ValueError('bounded initialization outer retries')
    def bind(self):
        if self.ready:return 0
        for i in range(4):put(self.ends,i*8,0xffffffff)
        for i in range(16):put(self.index,i*8+4,0xffffffff)
        self.bound_base=0;self.bound_pointer=TABLE;self.bound_count=len(self.c['defaults']);self.actions.append('diagnostic:8fe')
        result=self.initialize()
        if result==0:self.ready=True
        return result
    def result(self):
        rows=[]
        for operation in self.c['operations']:
            returned={'initialize':self.initialize,'bind':self.bind,'copy':self.copy_backup,'dump':self.dump_storage}[operation]()
            rows.append(dict(returned=returned,flash_sha256=digest(self.flash),backup_sha256=digest(self.backup),
                sector_cache_sha256=digest(self.ends),key_cache_sha256=digest(self.index),pending_replace=self.pending,
                maintenance_flag=self.flag,duplicate_guard=int(self.duplicate),ready=int(self.ready),
                default_pointer=self.bound_pointer,default_count=self.bound_count,base=self.bound_base,heap_active=self.heap is not None))
        return dict(actions=self.actions,rows=rows)


def contract(c):
    if len(c['sectors'])!=4 or len(c['backup_sectors'])!=4 or not c['defaults']:raise ValueError('bounded storage/defaults')
    if not c['operations'] or any(op not in ('initialize','bind','copy','dump') for op in c['operations']):raise ValueError('bounded operations')
    if c['stale_cache'] and not c['ready'] and c['operations']!=['bind']:raise ValueError('stale backing only in binding fixtures')
    return Model(c).result()


def native_vectors():
    cases=[];baseline=gc_vectors()['cases'][0]
    def entry(status=2,offset=20,bad=False,payload=b'payload'):
        return dict(key='upgrade',offset=offset,state=status,bad_crc=bad,total_override=None,payload_hex=payload.hex())
    def add(name,operations=None,**changes):
        c=baseline|dict(name=name,operations=operations or ['initialize'],sectors=[sector() for _ in range(4)],records=[],source_cache=False,
            ready=False,stale_cache=False,prior_pointer=TABLE,prior_count=2,prior_base=0,backup_handle=True,active_handle=True,
            fail_alloc=False,copy_read_error=0,copy_write_error=0,copy_short_read=0,dump_read_error=0,
            backup_sectors=[sector() for _ in range(4)],backup_records=[])|changes
        c.pop('expected',None);c['expected']=contract(c);cases.append(c)
    add('initialize_clean');add('bind_clean',['bind'])
    add('bind_stale_cache',['bind'],stale_cache=True,prior_pointer=0x81348888,prior_count=77,prior_base=4096)
    add('bind_already_ready',['bind'],ready=True,stale_cache=True,prior_pointer=0x81348888,prior_count=77,prior_base=4096)
    live=[sector(primary=2)]+[sector() for _ in range(3)]
    add('initialize_live',sectors=live,records=[entry()]);add('initialize_incomplete',sectors=live,records=[entry(status=1)])
    add('initialize_marked',sectors=live,records=[entry(status=3)])
    add('initialize_duplicate',sectors=[sector(primary=3),sector(primary=2),sector(),sector()],records=[entry(status=3),entry(offset=4116,payload=b'newer')])
    add('initialize_incomplete_then_marked',sectors=live,records=[entry(status=1),entry(status=3,offset=62)])
    add('initialize_bad_crc',sectors=live,records=[entry(bad=True)]);add('initialize_deleted',sectors=live,records=[entry(status=4)])
    full=[sector(primary=3) for _ in range(4)];dead=[entry(status=4,offset=i*4096+20) for i in range(1,4)]
    add('initialize_marked_no_space',sectors=full,records=[entry(status=3)]+dead)
    add('initialize_dirty3_enough_empty',sectors=[sector(primary=3,dirty=3)]+[sector() for _ in range(3)],records=[entry()])
    add('initialize_dirty3_collect',sectors=[sector(primary=3,dirty=3),sector(),sector(primary=3),sector(primary=3)],
        records=[entry(),entry(status=4,offset=8212),entry(status=4,offset=12308)])
    add('initialize_retry_three',sectors=[sector(primary=3),sector(),sector(primary=3),sector(primary=3)],
        records=[entry(status=3),entry(status=4,offset=8212),entry(status=4,offset=12308)])
    invalid=[sector(valid=False)]+[sector() for _ in range(3)]
    add('initialize_backup_repair',sectors=invalid,backup_sectors=live,backup_records=[entry(payload=b'backup')])
    add('bind_backup_missing',['bind'],sectors=invalid,backup_handle=False)
    add('bind_again_after_error',['bind','bind'],sectors=invalid,backup_handle=False)
    add('initialize_backup_read_error',sectors=invalid,copy_read_error=2)
    add('initialize_backup_write_error',sectors=invalid,copy_write_error=2)
    add('initialize_backup_still_invalid',sectors=invalid,backup_sectors=invalid)
    add('initialize_initial_erase_error',sectors=invalid,fail_erase=1)
    add('initialize_defaults_erase_error',sectors=invalid,backup_handle=False,fail_erase=2)
    add('copy',['copy'],sectors=live,records=[entry(payload=b'active')],backup_sectors=live,backup_records=[entry(payload=b'backup')])
    add('copy_missing_source',['copy'],backup_handle=False);add('copy_missing_active',['copy'],active_handle=False)
    add('copy_alloc_error',['copy'],fail_alloc=True);add('copy_read_error',['copy'],copy_read_error=3)
    add('copy_write_error',['copy'],copy_write_error=2);add('copy_short_read',['copy'],copy_short_read=1)
    add('dump',['dump']);add('dump_missing_active',['dump'],active_handle=False)
    add('dump_alloc_error',['dump'],fail_alloc=True);add('dump_read_error',['dump'],dump_read_error=3)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=2000000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    if memory.read(0x80c32e8c,1024)!=table():raise ValueError('CRC table')
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},crc_table_sha256=digest(table()),
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Native initializer/callbacks, defaults binding/readiness, GC/default restore, four-block copy and diagnostic dump execute over synthetic services.',
            'Read/write/erase/rewrite, allocation and memory/string/logging services are supplied; rewrite replaces array bytes, without modeling device atomicity.',
            'Record search may read up to 32 bytes past the logical four-sector window; this runner supplies explicit erased adjacent read backing and forbids writes there.',
            'Selected complete/short backup reads, heap/driver faults, finite repair/retry paths; no device boot, physical backup, persistence, real handles or concurrency guarantee.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.vectors,a.validation,a.decompiled)):p.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect environment initialization: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
