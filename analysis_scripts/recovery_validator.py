#!/usr/bin/env python3
"""Read-only boot recovery checks with synthetic partitions and crypto services.

SHA-256 hardware wrappers and ECDSA arithmetic are supplied. This neither enters
recovery nor changes partitions, environment, counters or firmware on a device.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
else:
    from sensorhub_memory import StartupMemory

BOOT_HASH='44cd83c0d09864c6101e9825bd3c77d7fac314584d0408b378dd56c2aac5736a'
KEY_HASH='436da64f07264e8d1ddf568e7ec0edce6e52ea0f469af4ca54a36a2761aff547'
FILE=0x81200000
OUTPUT=0x81120000
HEADER=0x81100000
BUFFER=0x81110000
CONFIG=dict(raw_crc=0x80c00b52,crc=0x80c00b24,metadata=0x80c0e578,image=0x80c0e6ea,
    partition=0x80c0e7e0,wrapper=0x80c0e9c2,signature=0x80c0e3c2,signature_callback=0x80c0e38c,
    alloc=0x80c1a308,free=0x80c1a312,zero=0x80c2e014,copy=0x80c2de38,strncpy=0x80c2e684,
    strncmp=0x80c2e5e8,open=0x80c0b7c0,read=0x80c0b82c,close=0x80c0b828,
    board_ota=0x80c01078,board_hw=0x80c01088,sha_init=0x80c2b932,sha_update=0x80c2b998,
    sha_final=0x80c2ba1c,crypto=0x80c2c5b4,clock=0x80c1642e,logger=0x80c1cd7a)
RANGES=((0x80c00b24,0x54),(0x80c0e144,0x2ac),(0x80c0e578,0x454),(0x80c2c5aa,0xa))
TARGETS=(0x80c00b24,0x80c00b52,0x80c0e578,0x80c0e6ea,0x80c0e7e0,0x80c0e9c2,
         0x80c0e3c2,0x80c0e38c,0x80c0e180,0x80c0e144)
LOGS={0x80c36eb0:'ota_absent',0x80c36ef8:'hw_unknown',0x80c36ed0:'hw_compare',
      0x80c36f14:'magic',0x80c36f44:'product',0x80c36d30:'signature_short',
      0x80c36cd8:'signature_alloc',0x80c36d0c:'signature_rejected'}


def digest(data):return hashlib.sha256(data).hexdigest()
def raw_crc(data,seed=0xffffffff):
    value=seed
    for byte in data:
        value^=byte
        for _ in range(8):value=(value>>1)^(0xedb88320 if value&1 else 0)
    return value&0xffffffff
def crc(data,seed=0):return raw_crc(data,seed^0xffffffff)^0xffffffff
def table():return struct.pack('<256I',*[raw_crc(bytes([i]),0) for i in range(256)])
def version(text):
    value=text.encode('ascii')
    if len(value)>15:raise ValueError('synthetic version is bounded to 15 bytes')
    return value.ljust(16,b'\0')


def metadata_bytes(c):
    raw=bytearray(48);raw[:8]=c['magic'].encode('ascii');struct.pack_into('<HIHH',raw,8,c['metadata_size'],c['body_field'],c['product'],c['variant'])
    raw[18:34]=version(c['version']);struct.pack_into('<I',raw,34,c['body_field']);raw[38]=c['metadata_hw']
    return bytes(raw)


def file_bytes(c):
    n=c['size'];image=bytearray((i*17+3)&255 for i in range(n))
    if n>=112:image[-112:-64]=metadata_bytes(c)
    if n>=64:image[-64:]=bytes((i*7+11)&255 for i in range(64))
    header=bytearray(72);header[:4]=c['header_magic'].encode('ascii');struct.pack_into('<I',header,16,n)
    header[20:36]=version(c['header_version']);checksum=raw_crc(header[:68])^int(c['bad_crc']);struct.pack_into('<I',header,68,checksum)
    result=header+bytes(4096-len(header))+image
    return bytes(result)


def strncpy(source,n):return source.split(b'\0',1)[0][:n].ljust(n,b'\0')
def equal_version(a,b,n):return a[:n].split(b'\0',1)[0]==b[:n].split(b'\0',1)[0]


class Model:
    def __init__(self,c):
        self.c=c;self.file=file_bytes(c);self.actions=[];self.output=bytearray(b'\xa5'*64);self.allocations={};self.crypto=[]
    def log(self,line):self.actions.append('log:error:'+format(line,'x'))
    def alloc(self,n):
        ok=self.c['allocation_failure']!=n;self.actions.append(('alloc:' if ok else 'alloc_fail:')+str(n))
        if ok:self.allocations[n]=dict(data=bytearray(b'\xa5'*n),freed=False)
        return ok
    def free(self,n):self.allocations[n]['freed']=True;self.actions.append('free:'+str(n))
    def read(self,offset,n,role,target):
        returned=n-1 if self.c['short_read']==role else n
        self.actions.append(f'read:{offset}:{n}:{returned}');target[:returned]=self.file[offset:offset+returned];return returned
    def metadata(self,expected):
        c=self.c;self.actions.append('board:ota')
        if not c['board_ota']:self.actions.append('log:ota_absent')
        self.actions.append('board:hw')
        if c['board_hw']==255:self.actions.append('log:hw_unknown')
        else:
            self.actions.append('log:hw_compare')
            if (c['board_hw']^c['metadata_hw'])&0xf0:self.log(0xb4);return 0
            if (c['board_hw']&15)>(c['metadata_hw']&15):self.log(0xba);return 0
        if c['magic']!=expected:self.actions.append('log:magic');return 0
        if c['product']!=155 or (expected=='HMZPSIGN' and c['variant']!=256):self.actions.append('log:product');return 0
        return 1
    def signature(self,callback=False):
        c=self.c;n=c['size']
        if n<=64:self.actions.append('log:signature_short');return 0
        signed=n-64;signature=bytearray(b'\xa5'*64);self.read(4096+signed,64,'signature',signature)
        if not self.alloc(4096):self.actions.append('log:signature_alloc');return 0
        self.actions.append('sha:init');hashed=bytearray();at=0;buffer=self.allocations[4096]['data']
        while at<signed:
            count=min(4096,signed-at);self.read(4096+at,count,'body',buffer);hashed.extend(buffer[:count]);self.actions.append('sha:update:'+str(count));at+=count
            if callback:self.actions.append(f'progress:{at}:{n}')
        self.actions.append('sha:final');self.free(4096)
        self.crypto.append(dict(digest_hex=digest(hashed),signature_sha256=digest(signature),key_sha256=KEY_HASH,curve=0x80c3f378,length=32))
        self.actions.append('crypto')
        if not c['crypto_result']:self.actions.append('log:signature_rejected');return 0
        return 1
    def image(self,verify,expected,out,n):
        c=self.c;self.actions.append('log:image')
        if c['size']<112:self.log(0x245);return 0
        metadata=bytearray(b'\xa5'*48)
        if self.read(4096+c['size']-112,48,'metadata',metadata)!=48:self.log(0x24e);return 0
        if not self.metadata(expected):return 0
        if verify and not self.signature():self.log(0x259);return 0
        if out is not None and n:
            out[:n]=strncpy(metadata[18:34],n);out[n-1]=0
        return 1
    def partition(self,wrapper):
        c=self.c
        if not self.alloc(72):self.log(0x29a);return 0
        header=self.allocations[72]['data'];header[:]=bytes(72);result=0
        selector=c['selector']
        if selector not in (0,1,8):self.log(0x2b1)
        else:
            self.actions.append('open:'+{0:'recovery0',1:'recovery1',8:'recovery_ota'}[selector])
            if c['open_failure']:self.log(0x2b7)
            else:
                if self.read(0,72,'header',header)!=72:self.log(0x2c2)
                elif header[:4]!=b'RECO':self.log(0x2c8)
                elif c['bad_crc']:self.log(0x2cf)
                else:
                    ver=bytearray(16);result=self.image(True if wrapper else c['verify'],'HMRVYSIG',ver,15)
                    if not result:self.log(0x2e1)
                    elif not equal_version(ver,header[20:36],15):self.log(0x2e9);result=0
                    elif not wrapper and c['has_output']:
                        n=min(c['output_len'],16);self.output[:n-1]=ver[:n-1];self.output[n-1]=0
                self.actions.append('close')
        self.free(72);return result
    def result(self):
        c=self.c;scope=c['scope']
        if scope=='crc':
            data=bytes.fromhex(c['data_hex']);result=raw_crc(data,c['seed']) if c['raw'] else crc(data,c['seed'])
        elif scope=='metadata':result=self.metadata(c['expected_magic'])
        elif scope=='signature':result=self.signature(c['callback'])
        elif scope=='image':result=self.image(c['verify'],c['expected_magic'],self.output if c['has_output'] else None,c['version_len'])
        elif scope=='partition':result=self.partition(c['wrapper'])
        else:raise ValueError('unsupported recovery scope')
        return dict(returned=result,actions=self.actions,output_sha256=digest(self.output),crypto=self.crypto,
                    allocations=[dict(size=n,sha256=digest(a['data']),freed=a['freed']) for n,a in sorted(self.allocations.items())])


def contract(c):
    if not 0<=c['size']<=16384 or not 0<c['output_len']<=32 or not 0<=c['version_len']<=16:raise ValueError('bounded sizes required')
    if len(c['magic'])!=8 or len(c['expected_magic'])!=8 or len(c['header_magic'])!=4:raise ValueError('magic width')
    return Model(c).result()


def native_vectors():
    cases=[]
    def add(name,scope,**changes):
        c=dict(name=name,scope=scope,size=512,magic='HMRVYSIG',expected_magic='HMRVYSIG',metadata_size=48,
            body_field=400,product=155,variant=256,metadata_hw=0x21,board_hw=255,board_ota=True,version='2.3.1',
            header_version='2.3.1',header_magic='RECO',bad_crc=False,selector=0,verify=True,wrapper=False,
            has_output=True,output_len=16,version_len=15,allocation_failure=0,open_failure=False,short_read='',crypto_result=1,callback=False)|changes
        c['input_hex']=(bytes.fromhex(c['data_hex']) if scope=='crc' else metadata_bytes(c) if scope=='metadata' else file_bytes(c)).hex()
        c['magic_low'],c['magic_high']=struct.unpack('<II',c['expected_magic'].encode('ascii'))
        c['expected']=contract(c);cases.append(c)
    for data in (b'',b'123456789',bytes(range(256))):
        for raw in (False,True):add('crc_'+str(len(data))+'_'+str(raw),'crc',data_hex=data.hex(),seed=0xffffffff if raw else 0,raw=raw)
    add('crc_custom_seed','crc',data_hex='12345678ab',seed=0x12345678,raw=True)
    add('metadata_valid','metadata');add('metadata_no_ota','metadata',board_ota=False)
    for board,meta in ((0x21,0x21),(0x21,0x22),(0x22,0x21),(0x21,0x31),(0x21,0xff)):
        add(f'metadata_hw_{board}_{meta}','metadata',board_hw=board,metadata_hw=meta)
    add('metadata_magic','metadata',magic='HMZPSIGN');add('metadata_product','metadata',product=156)
    add('metadata_recovery_variant_ignored','metadata',variant=65535)
    add('metadata_main_variant','metadata',magic='HMZPSIGN',expected_magic='HMZPSIGN',variant=1)
    add('metadata_main_valid','metadata',magic='HMZPSIGN',expected_magic='HMZPSIGN')
    add('metadata_size_body_ignored','metadata',metadata_size=64,body_field=0xffffffff)
    for n in (0,64,65,4159,4160,4161,8256):add('signature_size_'+str(n),'signature',size=n)
    add('signature_callback','signature',size=4161,callback=True)
    add('signature_alloc_failure','signature',allocation_failure=4096)
    add('signature_rejected','signature',crypto_result=0)
    add('signature_nonzero_result','signature',crypto_result=7)
    for role in ('signature','body'):add('signature_short_'+role,'signature',size=4161,short_read=role,crypto_result=0)
    add('image_valid','image');add('image_small','image',size=111);add('image_minimum','image',size=112)
    add('image_metadata_short','image',short_read='metadata');add('image_bad_magic','image',magic='HMZPSIGN')
    add('image_crypto_rejected','image',crypto_result=0);add('image_verify_disabled','image',verify=False,crypto_result=0)
    add('image_no_output','image',has_output=False);add('image_version_zero','image',version_len=0)
    add('image_size_field_ignored','image',metadata_size=64,body_field=123)
    for selector in (0,1,8,7):add('partition_selector_'+str(selector),'partition',selector=selector)
    add('partition_header_alloc_failure','partition',allocation_failure=72);add('partition_open_failure','partition',open_failure=True)
    add('partition_header_short','partition',short_read='header');add('partition_magic','partition',header_magic='FAIL')
    add('partition_crc','partition',bad_crc=True);add('partition_version_mismatch','partition',header_version='2.3.2')
    add('partition_crypto_rejected','partition',crypto_result=0);add('partition_no_output','partition',has_output=False)
    for n in (1,8,20):add('partition_output_'+str(n),'partition',output_len=n)
    add('partition_verify_disabled','partition',verify=False,crypto_result=0)
    add('partition_wrapper_forces_verify','partition',wrapper=True,verify=False,crypto_result=0)
    add('partition_wrapper_valid','partition',wrapper=True)
    add('partition_long_version','partition',version='123456789012345',header_version='123456789012345')
    return dict(schema=1,cases=cases)


def image_memory(archive):
    raw=archive.read('META/bootloader_sign.bin')
    if digest(raw)!=BOOT_HASH:raise ValueError('unexpected boot image')
    return StartupMemory(raw[0x400:],0x80c00000,0x26c,2,0x284,1)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from model')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    if memory.read(0x80c32e8c,1024)!=table() or digest(memory.read(0x80c36c94,64))!=KEY_HASH:raise ValueError('unexpected CRC table/key')
    return dict(boot_sha256=BOOT_HASH,key_sha256=KEY_HASH,crc_table_sha256=digest(table()),
        vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Partition I/O, allocation/memory/string services, board properties, time, SHA hardware wrappers and ECDSA arithmetic are supplied.',
            'Native CRC, metadata policy, SHA chunk orchestration, key/curve bridge and partition/wrapper control flow execute against synthetic inputs.',
            'Short reads are bounded synthetic service results; they do not establish a signature bypass or device reachability.',
            'No flash writes, counter/environment updates, recovery entry, hardware execution or viable standalone boot path are performed/proved.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect recovery validator: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
