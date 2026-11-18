#!/usr/bin/env python3
"""Actual UID inside first-chip probe/BBT and supported-family workaround/probe."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import nand_probe_bbt_stack as joined
    from . import nand_identity_stack as identity
else:
    import nand_probe_bbt_stack as joined
    import nand_identity_stack as identity

probe=joined.probe
qspi=probe.qspi
UID=identity.UID
IDENTITY_RANGES=identity.EXTRA_RANGES


def chip_index(scope):
    if scope not in ('bbt','supported'):raise ValueError('unknown probe auxiliary scope')
    return 0 if scope=='bbt' else 3


def ranges(scope):
    chip_index(scope)
    base=joined.RANGES if scope=='bbt' else probe.RANGES
    return tuple(dict.fromkeys(base+IDENTITY_RANGES))
def data_ranges(scope):
    base=joined.DATA_RANGES if scope=='bbt' else probe.DATA_RANGES
    p=identity.identity.facts()[chip_index(scope)]
    return tuple(dict.fromkeys(base+((p['sequence_pointer'],len(p['sequence'])*2),)))


class UidMixin:
    def init_uid(self):
        self.p=self.c['identity_descriptor'];self.uid=bytearray(b'\xa5'*128);self.uid_length=self.c['initial_uid_length']
        self.features[224]=self.c['e0'];self.feature_regs=self.features
        self.uid_at=0;self.in_uid=False;self.aux_status_reads=0;self.e0_reads=0;self.export_return=None
    def write(self,offset,value,size=4):
        if offset==12 and value>>24==3:self.uid_at=0
        if offset==256 and self.regs[12]>>24==31 and self.regs[0]==224 and not self.c['apply_writes']:
            return qspi.Model.write(self,offset,value,size)
        return super().write(offset,value,size)
    def read(self,offset,size=4):
        if offset!=256:return super().read(offset,size)
        op=self.regs[12]>>24;reg=self.regs[0]
        if op==3:
            index=reg//32;data=identity.identity.uid_bytes(index,index==self.c['first_good'])
            value=int.from_bytes(data[self.uid_at:self.uid_at+size],'little');self.uid_at+=size
        elif op==15 and reg==224:
            self.feature_reads+=1;values=self.c['e0_reads'];i=self.e0_reads;self.e0_reads+=1
            value=values[i] if i<len(values) else self.features[224]
        elif op==15 and reg==192 and not self.c.get('native_bbt_stack',False):
            self.feature_reads+=1;values=self.c['responses'];value=values[min(self.aux_status_reads,len(values)-1)];self.aux_status_reads+=1
        elif op==15 and self.in_uid and reg!=192:
            self.feature_reads+=1;value=self.features.get(reg,0)^int(self.c['uid_mismatch'])
        else:return super().read(offset,size)
        self.rx+=size;self.actions.append(f'r:{offset}:{size}:{value}');return value
    def bus(self,opcode,address=0,address_bytes=0,count=0,dummy=0,lines=1,write=True,private=False,status=False):
        if private:raise ValueError('selected direct auxiliary transfer')
        data=self.transfer(opcode,address,address_bytes,count,write,bytes(self.buffer[:count]) if write and count else None,dummy=dummy,lines=lines)
        if self.stopped:return None,None
        if not write and count and not status:self.buffer[:count]=data
        return 0,data[0] if status else None
    def get(self,reg):return self.bus(15,reg,1,1,write=False,status=True)
    def set(self,reg,value):
        saved=self.buffer;self.buffer=bytearray(512);self.buffer[0]=value&255
        status=self.bus(31,reg,1,1)[0];self.buffer=saved;return status
    def poll(self,limit,sleep=False):return identity.maintenance.Model.poll(self,limit,sleep)
    def compat(self):return identity.Model.compat(self)
    def level(self,value):return identity.Model.level(self,value)
    def run_workaround(self):
        self.actions.append('probe_workaround_native');identity.Model.check(self)
    def run_uid(self):
        self.actions.append('probe_uid_native');self.in_uid=True
        try:identity.Model.unique(self)
        finally:self.in_uid=False
    def finish_uid(self,result):
        row=result['rows'][0]
        if not self.stopped and self.c['aux_export_uid']:
            self.buffer[0]=self.uid_length;self.buffer[1:1+self.uid_length]=self.uid[:self.uid_length]
            self.actions.append('copy_uid:'+str(self.uid_length));self.export_return=0
            row['buffer_sha256']=qspi.digest(self.buffer)
        row.update(uid_length=self.uid_length,uid_sha256=qspi.digest(self.uid),status_reads=self.aux_status_reads,
            e0_reads=self.e0_reads,feature_registers={str(k):v for k,v in sorted(self.features.items())},aux_export_return=self.export_return)
        return result


class BbtModel(UidMixin,joined.Model):
    def __init__(self,c):super().__init__(c);self.init_uid()
    def run(self):return self.finish_uid(joined.Model.run(self))


class SupportedModel(UidMixin,probe.Model):
    def __init__(self,c):super().__init__(c);self.init_uid()
    def run(self):return self.finish_uid(probe.Model.run(self))


def contract(c,scope):
    i=chip_index(scope)
    if c['probe_id']!=probe.CHIPS[i]['id'] or c['probe_delayed_rounds'] or not c['native_probe_aux'] or not c['native_identity']:raise ValueError('auxiliary selected chip')
    if c['identity_descriptor']!=identity.identity.facts()[i] or not 0<=c['initial_uid_length']<=128 or not -1<=c['first_good']<16:raise ValueError('original UID backing')
    if len(c['e0_reads'])>16 or any(not 0<=v<=255 for v in c['e0_reads']+[c['e0']]) or c['uid_feature_write_error']:raise ValueError('auxiliary feature input')
    if scope=='bbt':joined.contract(c|dict(native_identity=False,native_probe_aux=False))
    else:probe.contract(c|dict(native_identity=False,native_probe_aux=False))
    return (BbtModel if scope=='bbt' else SupportedModel)(c).run()


def native_vectors(scope='bbt'):
    i=chip_index(scope);base=(joined if scope=='bbt' else probe).native_vectors()['cases'][0];cases=[]
    def add(name,**changes):
        c=base|dict(name=name,native_probe_aux=True,native_identity=True,identity_descriptor=identity.identity.facts()[i],
            probe_id=probe.CHIPS[i]['id'],e0=0,e0_reads=[],apply_writes=True,uid_mismatch=False,uid_feature_write_error=False,
            first_good=0,initial_uid_length=17,aux_export_uid=False)|changes
        c['expected']=contract(c,scope);cases.append(c)
    if scope=='bbt':
        add('uid_bbt_primary');add('uid_bbt_second_copy',first_good=1);add('uid_bbt_last_copy',first_good=15)
        add('uid_bbt_no_valid_copy',first_good=-1,aux_export_uid=True)
        add('uid_bbt_feature_error',uid_mismatch=True,aux_export_uid=True)
        add('uid_bbt_ecc_error',responses=[32,0],aux_export_uid=True)
        add('uid_bbt_export',aux_export_uid=True)
        add('uid_bbt_no_table',bbt_records={},bbt_record_hex={})
        backup={'1022':dict(bad=[1,3,7])}
        add('uid_bbt_backup',bbt_records=backup,bbt_record_hex={k:joined.recovery.bbt.record(v).hex() for k,v in backup.items()})
        add('uid_bbt_erase_error',bbt_records=backup,bbt_record_hex={k:joined.recovery.bbt.record(v).hex() for k,v in backup.items()},responses=[0]*10+[4,0])
        add('uid_bbt_wrapper',probe_entry='wrapper')
    else:
        add('aux_supported_zero');add('aux_supported_level_reset',e0=2)
        add('aux_supported_unconfirmed',e0=2,apply_writes=False)
        add('aux_supported_second_level_attempt',e0=2,e0_reads=[2,2,2,0])
        add('aux_supported_uid_second',first_good=1)
        add('aux_supported_uid_ecc',responses=[32,0],aux_export_uid=True)
        add('aux_supported_uid_feature_error',uid_mismatch=True,aux_export_uid=True)
        add('aux_supported_no_uid_copy',first_good=-1)
        add('aux_supported_export',aux_export_uid=True)
        add('aux_supported_bbt_error_ignored',probe_bbt_status=-9)
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
            'Original UID acquisition/verification/export executes inside the selected probe; first-chip cases join actual BBT, supported-family cases join actual reset/level workaround with supplied BBT.',
            'ID/UID/status/register streams, clocks/power/mutex/library/peripheral effects are authored; no physical UID provenance, persistent repairs or electrical operation is established.',
            'Success/stale export observations are selected control and data flow, not proof of valid unique device identity or standalone boot.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('bbt','supported'),default='bbt')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect probe auxiliary integration: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
