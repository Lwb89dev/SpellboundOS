#!/usr/bin/env python3
"""Original main cache CSR loops and RTOS critical-section bodies over authored state."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_dma_irq as prior
else:
    import main_dma_irq as prior

base=prior.base
CONFIG=dict(all=0x7029fe74,prepare=0x7029fea0,finish=0x7029ff04,invalidate=0x7029ff68,
    save=0x80d379ee,restore=0x80d37a1a,context=0x80d41190,enter=0x80d3a062,exit=0x80d3a0ae,trace=0x80d33720)
RANGES=((CONFIG['all'],44),(CONFIG['prepare'],100),(CONFIG['finish'],100),(CONFIG['invalidate'],100),
    (CONFIG['save'],44),(CONFIG['restore'],24),(CONFIG['context'],10),(CONFIG['enter'],76),(CONFIG['exit'],76),(CONFIG['trace'],26))
SCHED=0x80c07e5c
CURRENT=0x80c07fa8
CONTEXT=0x80c121a4
TRACE_ENABLED=0x80c44244
TRACE_TABLE=0x80dff708
THREAD=0x81348000
COOKIE=0x81349000
END=0x70000000
BOUND=5000
MASK=0xffffffff
CSR=(0x300,0x7ca,0x7cb,0x7cc)
RETURNS={'all':0x7029fe84,'prepare':0x7029febc,'finish':0x7029ff20,'invalidate':0x7029ff84}


class Model:
    def __init__(self,c):
        self.c=c;self.actions=[];self.rows=[];self.stopped=None;self.depth=c['depth'];self.saved=0xa5a5a5a5
        self.csrs=dict(zip(CSR,(c['mstatus'],c['control'],c['initial_address'],c['initial_command'])))
        self.commands=0;self.readbacks=0;self.fences=0;self.table=[0xa5a5a5a5]*12
    def ram_read(self,at,size=4):
        value={SCHED:self.c['scheduler'],CURRENT:THREAD,CONTEXT:self.c['context'],TRACE_ENABLED:self.c['trace_enabled'],THREAD+80:self.depth}[at]
        self.actions.append(f'ram_r:{at}:{size}:{value}');return value
    def trace(self,key,value):
        self.actions.append(f'trace:{key}:{value}')
        if self.ram_read(TRACE_ENABLED,1):self.table[key]=value;self.actions.append(f'ram_w:{TRACE_TABLE+key*4}:4:{value}')
    def csr_read(self,reg):
        if reg==0x7cb:
            values=self.c['readbacks'];self.csrs[reg]=values[min(self.readbacks,len(values)-1)];self.readbacks+=1
        value=self.csrs[reg];self.actions.append(f'csr_r:{reg}:{value}');return value
    def csr_write(self,reg,value):
        value&=MASK;self.csrs[reg]=value;self.actions.append(f'csr_w:{reg}:{value}')
        if reg==0x7cc:self.commands+=1
    def depth_write(self,value):
        self.depth=value&MASK;self.actions.append(f'ram_w:{THREAD+80}:4:{self.depth}')
    def enter(self):
        self.trace(9,3);self.csr_write(0x300,self.csr_read(0x300)&~8);self.trace(9,1)
        if self.ram_read(SCHED):
            self.ram_read(CURRENT);value=self.ram_read(THREAD+80);self.depth_write(value+1)
            self.ram_read(CURRENT)
            if self.ram_read(THREAD+80)==1:self.trace(6,1)
    def exit(self):
        if not self.ram_read(SCHED):return
        self.ram_read(CURRENT)
        if not self.ram_read(THREAD+80):return
        self.ram_read(CURRENT);value=self.ram_read(THREAD+80);self.depth_write(value-1)
        self.ram_read(CURRENT)
        if not self.ram_read(THREAD+80):
            self.trace(6,0);self.trace(9,2);self.csr_write(0x300,self.csr_read(0x300)|8);self.trace(9,0)
    def save(self,caller,standalone=False):
        self.trace(7,caller)
        if self.ram_read(CONTEXT):
            if standalone:self.saved=0
        else:self.enter()
    def restore(self):
        if not self.ram_read(CONTEXT):self.exit()
    def command(self,value):
        if self.commands>=self.c['command_limit']:
            self.stopped=dict(kind='command_bound',limit=self.c['command_limit']);return False
        self.csr_write(0x7cc,value);return True
    def operation(self,op):
        kind=op['kind'];start=op['start'];size=op['size'];self.actions.append(f'op:{kind}:{start}:{size}')
        if kind=='enter':self.enter();return None
        if kind=='exit':self.exit();return None
        if kind=='save':self.save(END,True);return None
        if kind=='restore':self.restore();return None
        if kind!='all' and (start==0 or start&0x80000000):return 0
        self.save(RETURNS[kind])
        if kind=='all':
            if not self.command(6):return None
        elif self.csr_read(0x7ca)&2:
            self.csr_write(0x7cb,start&~31);end=(start+size)&MASK
            while True:
                if not self.command({'prepare':1,'finish':2,'invalidate':0}[kind]):return None
                if self.csr_read(0x7cb)>=end:break
        else:self.actions.append('fence');self.fences+=1
        self.restore();return 0
    def run(self):
        for op in self.c['operations']:
            returned=self.operation(op)
            self.rows.append(dict(returned=returned,stopped=self.stopped,csrs={str(k):v for k,v in sorted(self.csrs.items())},depth=self.depth,
                trace_table=list(self.table),saved_word=self.saved,commands=self.commands,readbacks=self.readbacks,fences=self.fences))
            if self.stopped:break
        return dict(actions=self.actions,rows=self.rows)


def contract(c,scope='range'):
    if scope not in ('range','critical') or c['scope']!=scope:raise ValueError('cache-control scope')
    words=('mstatus','control','initial_address','initial_command','depth','scheduler','context','restore_arg')
    if any(not 0<=c[k]<=MASK for k in words) or not 0<=c['trace_enabled']<=255:raise ValueError('RTOS/CSR input words')
    if not 1<=c['command_limit']<=16 or not c['readbacks'] or len(c['readbacks'])>16 or any(not 0<=v<=MASK for v in c['readbacks']):raise ValueError('bounded CSR feedback')
    ops=c['operations'];allowed=('all','prepare','finish','invalidate') if scope=='range' else ('enter','exit','save','restore','prepare','finish')
    if not 1<=len(ops)<=8 or any(op['kind'] not in allowed or not 0<=op['start']<=MASK or not 0<=op['size']<=MASK for op in ops):raise ValueError('bounded operation sequence')
    return Model(c).run()


def native_vectors(scope='range'):
    cases=[]
    def op(kind,start=0x1003,size=64):return dict(kind=kind,start=start,size=size)
    def add(name,kind='prepare',start=0x1003,size=64,operations=None,**changes):
        c=dict(name='main_cache_control_'+name,scope=scope,mstatus=0xa5a50008,control=2,initial_address=0x88776655,initial_command=0xcc,
            depth=0,scheduler=1,context=0,trace_enabled=1,restore_arg=0xdeadbeef,command_limit=16,readbacks=[0x1060],operations=operations or [op(kind,start,size)])|changes
        c['expected']=contract(c,scope);cases.append(c)
    if scope=='range':
        for kind in ('prepare','finish','invalidate'):
            add(kind+'_ready',kind);add(kind+'_disabled',kind,control=0)
            add(kind+'_unrelated_control',kind,control=0x80000001);add(kind+'_all_control_bits',kind,control=MASK)
            add(kind+'_multi_readback',kind,readbacks=[0x1000,0x1020,0x1040,0x1060])
            add(kind+'_backward_readback',kind,readbacks=[0x1020,0x1000,0x1043])
            add(kind+'_zero_aligned',kind,start=0x1000,size=0,readbacks=[0x1000])
            add(kind+'_zero_unaligned',kind,size=0,readbacks=[0x1000,0x1003])
            add(kind+'_wrapped_end',kind,start=0x1000,size=0xfffff000,readbacks=[0x1000])
            add(kind+'_context_bypass',kind,context=1)
            add(kind+'_stalled',kind,readbacks=[0x1000],command_limit=4)
        add('skip_zero',start=0);add('skip_high_half',start=0x80000000);add('skip_negative_one',start=MASK)
        add('last_positive',start=0x7fffffff,size=1,readbacks=[0x80000000])
        add('all_enabled','all');add('all_disabled','all',control=0);add('all_context','all',context=1);add('all_runtime_off','all',scheduler=0)
        add('trace_disabled',trace_enabled=0);add('repeated_prepare_finish',operations=[op('prepare'),op('finish')],readbacks=[0x1060,0x1060])
    elif scope=='critical':
        add('runtime_on_pair',operations=[op('enter'),op('exit')]);add('runtime_off_pair',operations=[op('enter'),op('exit')],scheduler=0)
        add('disabled_mie_pair',operations=[op('enter'),op('exit')],mstatus=0xa5a50000)
        add('nested_pair',operations=[op('enter'),op('enter'),op('exit'),op('exit')])
        add('existing_depth_pair',operations=[op('enter'),op('exit')],depth=2)
        add('enter_depth_wrap',operations=[op('enter'),op('exit')],depth=MASK)
        add('empty_exit',operations=[op('exit')],mstatus=0xa5a50000)
        add('depth_one_exit',operations=[op('exit')],depth=1,mstatus=0xa5a50000)
        add('depth_two_exit',operations=[op('exit')],depth=2)
        add('save_restore_normal',operations=[op('save'),op('restore')])
        add('save_restore_context',operations=[op('save'),op('restore')],context=1)
        add('save_restore_nonboolean_context',operations=[op('save'),op('restore')],context=MASK)
        add('restore_argument_ignored',operations=[op('save'),op('restore')],restore_arg=0)
        add('cache_existing_depth',depth=2);add('cache_mie_disabled',mstatus=0xa5a50000)
        add('cache_runtime_off',scheduler=0);add('cache_runtime_nonboolean',scheduler=2)
        add('cache_trace_nonboolean',trace_enabled=255)
        add('cache_context_disabled_control',context=1,control=0)
        add('cache_stalled_critical',command_limit=3,readbacks=[0x1000])
        add('cache_stalled_context',command_limit=3,readbacks=[0x1000],context=1)
        add('trace_disabled_pair',operations=[op('enter'),op('exit')],trace_enabled=0)
    else:raise ValueError('cache scope')
    return dict(schema=1,bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());memory=base.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{at:08x}_{n:x}':base.digest(memory.read(at,n)) for at,n in RANGES},
        export_sha256={f'{at:08x}.c':base.digest((decompiled/f'{at:08x}.c').read_bytes()) for at,n in RANGES},native_validation=report,
        native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original cache routines, wrapper save/restore/context query, critical enter/exit and trace bodies execute over authored scheduler/current-thread/depth/context/diagnostic state and CSR inputs.',
            'CSR address readbacks are explicitly supplied sequences, not a simulated hardware stride. Stalled cases stop at a harness command bound before another command; this is not a firmware timeout or normal return.',
            'The three guarded fence instructions are recorded and supplied as no-ops because the emulator does not implement their userop. No live ordering/cache completion, IRQ delivery/scheduling, physical coherency/timing/data movement/persistence/restoration or standalone boot is established.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('range','critical'),default='range')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main cache/critical paths: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
