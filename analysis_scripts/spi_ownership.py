#!/usr/bin/env python3
"""Bounded host contracts for SPI bus ownership, callbacks and power references.

The generic DMA behavior describes supplied non-null callbacks. The reviewed
optical startup table has no DMA operations and its probe chooses polling.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import SENSOR, SENSOR_HASH, uint
else:
    from sensorhub_memory import StartupMemory
    from zrpc_packets import SENSOR, SENSOR_HASH, uint

TARGETS = (0x80f8965c,0x80f896d8,0x80f89756,0x80f899aa,0x80f89a6a,
    0x80f7b404,0x80f7b3e8,0x80f7b328,0x80f7b2d4,0x80f7b2c0,0x80f7bdbc,
    0x80f7304c,0x80f73152,0x80f897bc,0x80f898ae,0x80f802de,0x80f80382)


def transfer_plan(*, dma=False, table_present=True, operation_present=True, cs_present=True,
                  take_result=0, operation_result=0, release_result=0, mutex_result=0):
    for value in (dma,table_present,operation_present,cs_present):
        if type(value) is not bool: raise ValueError('branch selectors must be bool')
    for status in (take_result,operation_result,release_result,mutex_result): uint(status,32)
    if not table_present or not operation_present:
        return dict(result=0,trace=[],release_deferred=False)
    trace=['mutex_take']
    if cs_present: trace.append('select')
    if cs_present and take_result:
        trace.extend(['deselect','mutex_release'])
        return dict(result=-14,trace=trace,release_deferred=False)
    trace.append('dma_operation' if dma else 'poll_operation')
    if dma and operation_result == 0:
        return dict(result=0,trace=trace,release_deferred=True)
    if cs_present: trace.append('deselect')
    trace.append('mutex_release')
    return dict(result=-14 if operation_result else 0,trace=trace,release_deferred=False)


def completion_plan(*, dma_now, user_callback=True, cs_present=True):
    if any(type(value) is not bool for value in (dma_now,user_callback,cs_present)):
        raise ValueError('completion selectors must be bool')
    trace=(['deselect'] if cs_present else [])+['mutex_release'] if dma_now else []
    if user_callback: trace.append('user_callback')
    return dict(result=0,trace=trace)


def reference_step(count, *, enable, callback_present=True):
    uint(count,16)
    if type(enable) is not bool or type(callback_present) is not bool:
        raise ValueError('reference selectors must be bool')
    updated=(count+1)&0xffff if enable else max(0,count-1)
    invoke=(updated != 0 if enable else updated == 0) and callback_present
    return dict(count=updated,invoke_callback=invoke)


def chip_select_store(bank,mask,*,selected):
    uint(bank,32);uint(mask,32)
    if type(selected) is not bool or bank+0x14 > 0xffffffff:
        raise ValueError('invalid bounded GPIO store')
    return dict(address=bank+(0x14 if selected else 0x10),value=mask)


def register_request(register, *, value=None):
    uint(register,8)
    if value is None:return bytes((register,0x80,0))
    uint(value,8)
    return bytes((register,0,value))


def register_output(result_word,response,previous):
    uint(result_word,32);uint(previous,8)
    if not isinstance(response,bytes) or len(response)!=3:raise ValueError('need the three-byte native buffer')
    return response[2] if result_word==0 else previous


def evidence(archive,decompiled,validation,polling):
    data=archive.read(SENSOR)
    if hashlib.sha256(data).hexdigest()!=SENSOR_HASH: raise ValueError('requires reviewed sensor image')
    m=StartupMemory(data)
    ops=struct.unpack('<9I',m.read(0x80f1589c,36))
    device_ops=struct.unpack('<5I',m.read(0x80f15888,20))
    if ops[5:]!=(0,0,0,0) or device_ops!=(0x80f7b2c0,0x80f7b404,0x80f7b3e8,0x80f7b328,0x80f7b2d4):
        raise ValueError('reviewed SPI tables differ')
    raw=validation.read_bytes();execution=json.loads(raw)
    if (execution['public_transfer_cases'],execution['completion_calls'],execution['chip_select_calls'],
            execution['reference_cases'],execution['native_invocations'])!=(26,8,2,12,48) or execution['hardware_execution'] is not False:
        raise ValueError('unexpected ownership execution report')
    raw_poll=polling.read_bytes();poll=json.loads(raw_poll)
    cases={case['name']:case for case in poll['cases']}
    if poll['case_count']!=13 or len(cases)!=13 or poll['hardware_execution'] is not False:
        raise ValueError('unexpected integrated polling execution report')
    final_timeout=cases['read_timeout_after_final_byte']
    if (final_timeout['result'],final_timeout['output_byte'],final_timeout['rx_reads'])!=(-14,165,3):
        raise ValueError('reviewed final-byte timeout result differs')
    for name in ('read_missing_operations','read_dma_unavailable'):
        case=cases[name]
        if (case['result'],case['output_byte'],case['tx_bytes'],case['events'])!=(0,0,[],[]):
            raise ValueError('reviewed no-operation read result differs')
    return dict(sensor_sha256=SENSOR_HASH,initial_bus_ops=list(ops),device_ops=list(device_ops),
        native_validation=execution,validation_sha256=hashlib.sha256(raw).hexdigest(),
        polling_validation=poll,polling_validation_sha256=hashlib.sha256(raw_poll).hexdigest(),
        export_sha256={f'{a:08x}.c':hashlib.sha256((decompiled/f'{a:08x}.c').read_bytes()).hexdigest() for a in TARGETS},
        byte_range_sha256={f'{a:08x}_{n:x}':hashlib.sha256(m.read(a,n)).hexdigest()
            for a,n in ((0x80f8965c,0x34e),(0x80f7b2d4,0x98),(0x80f7b3e8,0x38),
                        (0x80f7bdbc,0xe),(0x80f1589c,36),(0x80f15888,20),
                        (0x80f7ed84,0x200),(0x80f7304c,0x40),(0x80f73152,0x2a),
                        (0x80f7b3a0,0x80))},
        chip_select=dict(take=chip_select_store(0x91003000,0x200,selected=True),
                         release=chip_select_store(0x91003000,0x200,selected=False)),
        examples=dict(poll=transfer_plan(),dma=transfer_plan(dma=True),
                      dma_unavailable=transfer_plan(dma=True,operation_present=False),
                      mutex_failure=transfer_plan(mutex_result=0xfffffffe),
                      completion=completion_plan(dma_now=True),completion_after_flag_clear=completion_plan(dma_now=False)),
        reference_examples=[dict(before=n,enable=enable,**reference_step(n,enable=enable))
                            for n in (0,1,2,65535) for enable in (False,True)],
        limitations=['Native cases stub mutex, diagnostics, operation and user callbacks; no DMA/hardware/scheduler execution.',
            'Integrated polling cases execute native HAL using synthetic SPI status/data and scaled timestamps.',
            'Stock initial optical table has no DMA operations; generic DMA examples use synthetic non-null operations.',
            'No concurrency, cancellation or exactly-once completion guarantee established.',
            'Callback consults current DMA flag; caller must establish mutation/lifetime contracts separately.',
            'GPIO offsets/mask are software stores, not a measured pinout or electrical level.',
            'Reference callbacks and 16-bit arithmetic are reconstructed; actual power state is unobserved.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive');parser.add_argument('--decompiled',type=Path,required=True)
    parser.add_argument('--validation',type=Path,required=True)
    parser.add_argument('--polling',type=Path,required=True);args=parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.validation,args.polling)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:
        parser.exit(2,f'Cannot inspect SPI ownership: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
