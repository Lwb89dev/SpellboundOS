#!/usr/bin/env python3
"""Main trap entry, interrupt dispatch, PLIC API and FreeRTOS port contracts.

The model below independently describes the original main-image bodies that
ValidateMainTrapIrq.java executes natively over authored state.  Static
evidence pins the original bytes, the startup copy that places them in RAM,
the original core/exception vector tables and every recovered interrupt
registration call site.  Nothing here executes vendor code.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .main_object_lifecycle import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    from main_object_lifecycle import image_memory
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
BOUND = 5000
END = 0x70000000

# Original RAM routines (startup copy .copy2: image 0x70dce45c -> 0x80d32e00).
CORE_DISPATCH = 0x80d35b10
EXTERNAL_DISPATCH = 0x80d35b24
TRAP_HANDLER = 0x80d35b60
ENABLE = 0x80d35bcc
DISABLE = 0x80d35c1c
REGISTER = 0x80d35c6c
MASK_ALL = 0x80d35cc8
RESTORE_ALL = 0x80d35cdc
TRACE_THREAD = 0x80d35d82
TRAP_ENTRY = 0x80d35e00
TRAP_MRET = 0x80d35f98
START_FIRST = 0x80d36000
START_MRET = 0x80d360ae
START_SCHEDULER = 0x80d37eca
YIELD_HANDLER = 0x80d37f32
TIMER_HANDLER = 0x80d37f42
SOFTWARE_HANDLER = 0x80d4118c
DEFAULT_HANDLER = 0x80d41188
IRQ_INIT = 0x80d411ac
IRQ_DEINIT = 0x80d41200
EXCEPTION_DISPATCH = 0x702a3ea4
PLIC_INIT = 0x702a3ee8
SYSCALL = 0x702a4088
YIELD_WRAPPER = 0x80d3965c

# Supplied callees.
TICK = 0x80d3974e            # xTaskIncrementTick
SWITCH = 0x80d398d6          # vTaskSwitchContext
SETUP_TIMER = 0x80d37e14     # vPortSetupTimerInterrupt
ASSERT = 0x80d364fa
MEMCPY = 0x7094aed8
MEMSET = 0x70947ce8

# Globals.
CURRENT = 0x80c07fa8         # pxCurrentTCB
TRACE_FLAG = 0x80c07fac
IN_TRAP = 0x80c121a4         # word read by the context query 0x80d41190
SAVED_MIE = 0x80c121a0
EXTERNAL_TABLE = 0x80c11c70  # 0x53 entries of {handler, argument, enabled, priority}
CORE_TABLE = 0x80c009f4      # 32 entries of {handler, argument, 0, 0}
EXCEPTION_TABLE = 0x70a1d418
ISR_STACK_WORD = 0x70a1d8ac
ISR_STACK = 0x80e00000
TRACE = 0x80dff7c8           # flag, cause, claim, name[0x13], frame mepc, magic
NEXT_COMPARE = 0x80c07de8
PLIC_PRIORITY = 0xe4000000
PLIC_ENABLE = 0xe4002000
PLIC_THRESHOLD = 0xe4200000
PLIC_CLAIM = 0xe4200004
MTIMECMP = 0xe6000008
EXTERNAL_COUNT = 0x53
FRAME = 0x198
SYSCALL_YIELD = 0xf0000000

CODE = (
    (CORE_DISPATCH, 0x14, '88bb46b86233ba7f778a2cea4b4a33f4fb86f3da0671fbf7eab83f80653e018b'),
    (EXTERNAL_DISPATCH, 0x3c, 'babbdcafedb39fa11af46b3e5d41a307b6be73e7498843e8586ff6659bfe4215'),
    (TRAP_HANDLER, 0x6c, 'd036bf1e8832533ae077de03a1e927168969abbfbbb5d1b0c658cda91eaeaeb6'),
    (ENABLE, 0x50, '7a8e3b17503d15a44209e59a374be175e44dab1ed9f355fe51bb3103ac0c8fb9'),
    (DISABLE, 0x50, '51626faf6abe3761d6df9216de9e01b6d00456ecf886b58607aed81cce6ef83d'),
    (REGISTER, 0x5a, '11492899c191b3ba3232ee8d2ff30276c7b08d3509818f8765c3a84b1cce5e39'),
    (MASK_ALL, 0x12, 'f831776b82328966a312a0beec9840b6509322862cc5019ae1b1ffc4d3e90120'),
    (RESTORE_ALL, 0x4a, '36c2e4125630d653fed9da3269304af0565067d26d891da6252fb64ace6b762e'),
    (0x80d35d28, 0x58, '18b106a8451dbf17da5892a079a717c7c800cd28c06863f482d2aeb3807b7909'),
    (TRACE_THREAD, 0x5a, '45e34d4fea6b6b0758ad1a6200b66ce44f6588a6051e13373d8d45b1d5d07086'),
    (TRAP_ENTRY, 0x19c, '36f8abd0fb94affc83450027895e6aa20e1a19adf243dbc1f0f5a318c857962d'),
    (START_FIRST, 0xb2, '4eef7d7daffbc826a41bb59542b4889fbef09ee6c0948a7f8c10db616c29b1b6'),
    (START_SCHEDULER, 0x68, '1cbae35395ef49d2f230ff01d93a30ccbb133a4a03feb816b33f303ff715baf5'),
    (YIELD_HANDLER, 0x10, '06948d2c1abd3f16c38219cab924478c98508c25028854dd34c7799f3351a3ab'),
    (TIMER_HANDLER, 0x4a, '895359a9f0fba3c2780e8243e9ae9282cebaeb9986d272faa8014b40b201da0a'),
    (SOFTWARE_HANDLER, 0x2, '7529d4e6ceb037815e2664a7277abb404b02f0bf9ddbf5c11658f52448221cba'),
    (IRQ_INIT, 0x54, '1b14148ef92da2e9aaa6268efb4b878440fa328d1ec985a13863c98ac537cfc6'),
    (IRQ_DEINIT, 0xc, 'f2d296c2a5ace9947af4e324c2fa881d8027626bb30827d670e641588d335669'),
    (EXCEPTION_DISPATCH, 0x42, 'e9328730393e699a42c8503df0c4a0cb09f4cded24dc3610db536da9ed38289f'),
    (PLIC_INIT, 0x3e, 'e8b155b72ac6e018da2725057d6c2df232ca201d6342307be5efa714c92b34f3'),
    (SYSCALL, 0x2a, 'dff8902cdd09c668178e37c7ccc786b0de1304aba185f1a172807c9d46c730f3'),
)
DATA = (
    (CORE_TABLE, 0x200, '78c066b735424fb59430fcf476cd487b181a014c8e7c58e72f87fd7b2f44205b'),
    (EXCEPTION_TABLE, 0x30, '111a703641e376dd404492bd14da104ef182f7848108786656a6bdc89273057e'),
    (ISR_STACK_WORD, 0x4, '762356294531c0c6384d9a6dc9ca778fd1c80dfc14d2f427b421da14a069f7e1'),
    (DEFAULT_HANDLER, 0x2, 'a179dbdd51c56d0988551f92535797bcf47ca0e7ef0400f364db54291cfa89aa'),
    (YIELD_WRAPPER, 0x14, '833ad5969ada2ff8f4f060672f34782ae454ad0608bfff0ba8cbe960672e1129'),
)
CORE_VECTORS = {3: SOFTWARE_HANDLER, 7: TIMER_HANDLER, 11: EXTERNAL_DISPATCH}
EXCEPTION_VECTORS = (0x702a3e88, 0x702a3e6c, 0x702a3e50, 0x702a3e34, 0x702a3e18, 0x702a3dfc,
                     0x702a3de0, 0x702a3dc4, 0x702a3d80, 0x702a3d88, 0x702a3d84, SYSCALL)
COPY = dict(source=0x70dce45c, destination=0x80d32e00, size=0x14d38)
STRINGS = ((0x70a1dcf4, b'..//./core/freertos/tasks.c'),
           (0x70a1de20, b'( listLIST_IS_EMPTY( pxDelayedTaskList ) )'),
           (0x70a1de4c, b'listCURRENT_LIST_LENGTH( &( pxReadyTasksLists[ uxTopPriority ] ) ) > 0'))
# Call sites of the original registration routine, with (irq, handler, argument)
# as recovered by the raw decoder below; None marks a runtime (object field) value.
REGISTRATIONS = (
    (0x70162552, 0x51, 0x70161582, 0),
    (0x70162e56, 0x16, 0x702a041c, 0x93000000),
    (0x70162e8e, 0x19, 0x702a041c, 0x93040000),
    (0x70162ec6, 0x1c, 0x702a041c, 0x93080000),
    (0x70162f08, 0x12, 0x702a041c, 0x92000000),
    (0x702942dc, 9, 0x70293d50, 0x91003000),
    (0x702942f4, 10, 0x70293d50, 0x91004000),
    (0x7029430c, 0x2a, 0x70293d50, 0x98005000),
    (0x70294324, 0x2b, 0x70293d50, 0x9a00a000),
    (0x7029433c, 0x2c, 0x70293d50, 0x9a00b000),
    (0x70294354, 0x2d, 0x70293d50, 0x9a00c000),
    (0x70294904, 0x4f, 0x702944a4, 0),
    (0x70294928, 0x50, 0x7029444c, 0),
    (0x70296180, 0xb, 0x70295c30, 0),
    (0x70296514, None, 0x70296530, None),
    (0x702970b4, 0xc, 0x702970e0, 0),
    (0x702a31a0, None, 0x702a2e74, None),
    (0x707bfa18, 0x10, 0x707bf926, 0),
)
# Direct jal calls of the registration routine inside the RAM copy.
DIRECT_REGISTRATIONS = (
    (0x80d37e58, 0xe, 0x80d37e08, 0),   # vPortSetupTimerInterrupt
    (0x80d4219c, 0xe, 0x80d42004, 0),
    (0x80d421b4, 0xc, 0x80d42018, 0),
    (0x80d421cc, 0xb, 0x80d4202c, 0),
    (0x80d42a58, 0xe, 0x80d429dc, 0),
)
CSRS = (0x3, 0x300, 0x304, 0x305, 0x340, 0x341, 0x342, 0x7c6, 0x7c7)
X = ('zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2', 's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
     'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6')
F = ('ft0', 'ft1', 'ft2', 'ft3', 'ft4', 'ft5', 'ft6', 'ft7', 'fs0', 'fs1', 'fa0', 'fa1', 'fa2', 'fa3',
     'fa4', 'fa5', 'fa6', 'fa7', 'fs2', 'fs3', 'fs4', 'fs5', 'fs6', 'fs7', 'fs8', 'fs9', 'fs10', 'fs11',
     'ft8', 'ft9', 'ft10', 'ft11')
HARNESS_STACK = 0x81001000
TASK_A_STACK = 0x81102000
TASK_B_FRAME = 0x81201e68
TCB_A = 0x81340000
TCB_B = 0x81341000
CODE_AREA = 0x81300000
QUIET = ((0x81000000, 0x81002000), (0x81100000, 0x81102000), (0x81200000, 0x81202000),
         (0x80dffc00, 0x80e00000))
OUT_OF_TABLE_HANDLER = 0x70001000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def frame_slots():
    """Integer register -> frame offset (x0 slot holds zero; sp slot holds the frame)."""
    slots = {name: 4 * index for index, name in enumerate(X) if index}
    return slots


def word(value):
    return value & MASK


class Model:
    """Independent model of the original routines, emitting the runner's actions."""

    def __init__(self, case):
        self.c = case
        self.mem = {}
        for address, data in case['memory']:
            for i, b in enumerate(bytes.fromhex(data)):
                self.mem[address + i] = b
        self.csr = {int(k): v for k, v in case['csrs'].items()}
        self.regs = dict(case['registers'])
        self.fregs = dict(case['fregisters'])
        self.actions = []
        self.claims = list(case['claims'])
        self.stubs = {int(k): v for k, v in case['stubs'].items()}

    # Memory and CSR primitives.
    def read(self, address, size=4):
        value = 0
        for i in range(size):
            at = address + i
            if at in self.mem:
                b = self.mem[at]
            else:
                b = self.original_byte(at)
            value |= b << (8 * i)
        return value

    def original_byte(self, at):
        if CORE_TABLE <= at < CORE_TABLE + 0x200:
            index, offset = divmod(at - CORE_TABLE, 16)
            value = CORE_VECTORS.get(index, 0) if offset < 4 else 0
            return (value >> (8 * (offset % 4))) & 255
        if EXCEPTION_TABLE <= at < EXCEPTION_TABLE + 0x50:
            index, offset = divmod(at - EXCEPTION_TABLE, 4)
            value = EXCEPTION_VECTORS[index] if index < len(EXCEPTION_VECTORS) else 0
            return (value >> (8 * offset)) & 255
        if ISR_STACK_WORD <= at < ISR_STACK_WORD + 4:
            return (ISR_STACK >> (8 * (at - ISR_STACK_WORD))) & 255
        raise ValueError(f'model read of unauthored byte {at:#x}')

    def write(self, address, size, value, record=True):
        value &= (1 << (8 * size)) - 1
        for i in range(size):
            self.mem[address + i] = (value >> (8 * i)) & 255
        if record and not any(lo <= address < hi for lo, hi in QUIET):
            self.actions.append(f'w:{address}:{size}:{value}')

    def csr_op(self, number, new=None):
        old = self.csr[number]
        if new is not None:
            self.csr[number] = new & MASK
        self.actions.append(f'csr:{number}:{old}:{self.csr[number]}')
        return old

    def claim(self):
        value = self.claims.pop(0)
        self.actions.append(f'r:{PLIC_CLAIM}:4:{value}')
        return value

    def call(self, address, *args):
        stub = self.stubs[address]
        if stub['args'] != len(args):
            raise ValueError('stub argument count')
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))
        kind = stub['kind']
        if kind == 'stop':
            raise Stopped(stub['label'])
        if kind == 'switch' and 'current' in stub:
            self.write(stub['current_address'], 4, stub['current'], record=False)
        if kind == 'memcpy':
            dst, src, n = args
            for i in range(n):
                self.mem[dst + i] = self.read(src + i, 1)
        if kind == 'memset':
            dst, value, n = args
            for i in range(n):
                self.mem[dst + i] = value & 255
        return stub.get('value')

    def handler(self, address, argument):
        if address == DEFAULT_HANDLER or address == 0 or address in self.stubs:
            return self.call(address, argument)
        if address == SOFTWARE_HANDLER:
            return None
        if address == TIMER_HANDLER:
            return self.timer()
        if address == EXTERNAL_DISPATCH:
            return self.external()
        raise ValueError(f'unmodelled handler {address:#x}')

    # PLIC API.
    def enable_bit(self, irq):
        address = PLIC_ENABLE + 4 * (irq >> 5)
        self.write(address, 4, self.read(address) | (1 << (irq & 31)))

    def disable_bit(self, irq):
        address = PLIC_ENABLE + 4 * (irq >> 5)
        self.write(address, 4, self.read(address) & ~(1 << (irq & 31)))

    def register(self, irq, handler, argument):
        number = irq & 0xefffffff
        if irq & 0x10000000:
            if number <= 15:
                entry = CORE_TABLE + 16 * (number + 16)
                self.write(entry, 4, handler)
                self.write(entry + 4, 4, argument)
        elif number <= 0x52:
            entry = EXTERNAL_TABLE + 16 * number
            self.write(entry, 4, handler)
            self.write(entry + 4, 4, argument)
            self.write(entry + 8, 4, 0)
            self.write(entry + 12, 4, 1)
            self.write(PLIC_PRIORITY + 4 * number, 4, 1)

    def enable(self, irq, on=True):
        number = irq & 0xefffffff
        if irq & 0x10000000:
            if number <= 16:
                bit = 1 << ((number + 16) & 31)
                old = self.csr[0x304]
                self.csr_op(0x304, old | bit if on else old & ~bit)
        elif number <= 0x52:
            (self.enable_bit if on else self.disable_bit)(number)
            self.write(EXTERNAL_TABLE + 16 * number + 8, 4, 1 if on else 0)

    def mask_all(self):
        value = self.csr_op(0x304)
        self.write(SAVED_MIE, 4, value)
        self.csr_op(0x304, 0)

    def restore_all(self):
        for irq in range(EXTERNAL_COUNT):
            entry = EXTERNAL_TABLE + 16 * irq
            if self.read(entry + 8):
                self.enable_bit(irq)
                self.write(PLIC_PRIORITY + 4 * irq, 4, self.read(entry + 12))
        self.csr_op(0x304, self.read(SAVED_MIE))

    def plic_init(self):
        for i in range(3):
            self.write(PLIC_ENABLE + 4 * i, 4, 0)
        self.call(MEMSET, PLIC_PRIORITY, 0, 0x150)
        self.write(PLIC_THRESHOLD, 4, 0)
        self.write(PLIC_PRIORITY, 4, 1)

    def irq_init(self):
        self.csr_op(0x304, 0)
        self.plic_init()
        for irq in range(EXTERNAL_COUNT):
            entry = EXTERNAL_TABLE + 16 * irq
            self.write(entry, 4, DEFAULT_HANDLER)
            for offset in (4, 8, 12):
                self.write(entry + offset, 4, 0)
        self.csr_op(0x304, self.csr[0x304] | 0x800)
        self.csr_op(0x304, self.csr[0x304] | 0x8)
        self.csr_op(0x300, self.csr[0x300] | 0x8)

    def irq_deinit(self):
        self.csr_op(0x300, self.csr[0x300] & ~0x8)
        self.plic_init()

    # Interrupt and exception paths.
    def external(self):
        claim = self.claim()
        if self.read(TRACE_FLAG, 1):
            self.write(TRACE + 8, 4, claim)
        entry = EXTERNAL_TABLE + 16 * claim
        handler, argument = self.read(entry), self.read(entry + 4)
        self.handler(handler, argument)
        self.write(PLIC_CLAIM, 4, claim)

    def timer(self):
        old = self.csr[0x304]
        self.csr_op(0x304, old & ~0x80)
        low, high = self.read(NEXT_COMPARE), self.read(NEXT_COMPARE + 4)
        self.write(MTIMECMP, 4, 0)
        self.write(MTIMECMP + 4, 4, high)
        self.write(MTIMECMP, 4, low)
        nxt = low + 1000
        self.write(NEXT_COMPARE, 4, nxt)
        self.write(NEXT_COMPARE + 4, 4, high + (nxt > MASK))
        self.csr_op(0x304, self.csr[0x304] | 0x80)
        if self.call(TICK):
            self.call(SWITCH)

    def exception(self, cause, epc, frame):
        handler = self.read(EXCEPTION_TABLE + 4 * cause)
        if handler == SYSCALL:
            if self.read(frame + 0x44) == SYSCALL_YIELD:
                self.call(SWITCH)
            self.write(frame + 0x28, 4, 0)
        else:
            self.handler(handler, epc) if handler in (0,) else self.call(handler, epc, frame)
        length = 4 if self.read(epc, 2) & 3 == 3 else 2
        self.write(frame + 0x84, 4, epc + length)

    def trace_thread(self):
        if not self.read(TRACE_FLAG, 1):
            return
        current = self.read(CURRENT)
        self.call(MEMCPY, TRACE + 0xc, current + 0x34, 0x13)
        self.write(TRACE + 0x20, 4, self.read(self.read(current) + 0x84))
        self.write(TRACE + 0x24, 4, 0xaabbccdd)

    def trap_handler(self, cause, epc, frame):
        flag = self.read(TRACE_FLAG, 1)
        self.write(IN_TRAP, 4, 1)
        if flag:
            self.write(TRACE, 4, 1)
            self.write(TRACE + 4, 4, cause)
        if cause & 0x80000000:
            code = cause & 0x7fffffff
            entry = CORE_TABLE + 16 * code
            self.handler(self.read(entry), self.read(entry + 4))
        else:
            self.exception(cause, epc, frame)
        self.trace_thread()
        if self.read(TRACE_FLAG, 1):
            self.write(TRACE, 4, 0)
        self.write(IN_TRAP, 4, 0)

    def restore_frame(self, frame, fcsr=True):
        """Common restore tail; returns final integer registers."""
        if fcsr:
            self.csr_op(0x3, self.read(frame + 0x190))
        self.csr_op(0x341, self.read(frame + 0x84))
        self.csr_op(0x300, self.read(frame + 0x80))
        regs = {name: self.read(frame + off) for name, off in frame_slots().items()}
        regs['sp'] = word(frame + FRAME)
        fregs = {name: '%016x' % self.read(frame + 0x90 + 8 * i, 8) for i, name in enumerate(F)}
        return regs, fregs

    def trap_entry(self):
        regs, fregs = self.regs, self.fregs
        t0 = regs['t0']
        hsp = self.csr[0x7c6]
        self.csr_op(0x340, t0)          # csrrw t0, mscratch, t0
        self.csr_op(0x7c6)              # csrr t0, 0x7c6
        self.csr_op(0x7c6, 0)           # csrw 0x7c6, zero
        self.csr_op(0x340, hsp)         # csrrw t0, mscratch, t0 (t0 holds 0x7c6)
        frame = word(regs['sp'] - FRAME)
        self.write(frame, 4, 0)
        for name, off in frame_slots().items():
            self.write(frame + off, 4, frame if name == 'sp' else regs[name])
        self.write(frame + 0x88, 4, self.csr_op(0x340))
        self.write(frame + 0x8c, 4, self.csr_op(0x7c7))
        fcsr = self.csr_op(0x3)
        for i, name in enumerate(F):
            self.write(frame + 0x90 + 8 * i, 8, int(fregs[name], 16))
        self.write(frame + 0x190, 4, fcsr)
        cause, epc, status = self.csr_op(0x342), self.csr_op(0x341), self.csr_op(0x300)
        self.write(frame + 0x84, 4, epc)
        self.write(frame + 0x80, 4, status)
        self.write(self.read(CURRENT), 4, frame)
        cause, epc = self.csr_op(0x342), self.csr_op(0x341)
        nested = self.read(IN_TRAP)
        self.trap_handler(cause, epc, frame)
        resumed = self.read(self.read(CURRENT))
        out = self.restore_frame(resumed)
        self.csr_op(0x7c7, self.read(resumed + 0x8c))
        self.csr_op(0x340, self.read(resumed + 0x88))
        self.csr_op(0x340, self.read(resumed + 0x14))
        self.csr_op(0x7c6, self.read(resumed + 0x88))
        self.csr_op(0x340, self.read(resumed + 0x88))
        return out, nested

    def start_first(self):
        self.csr_op(0x305, TRAP_ENTRY)
        frame = self.read(self.read(CURRENT))
        out = self.restore_frame(frame, fcsr=False)
        self.csr_op(0x7c7, self.read(frame + 0x8c))
        self.csr_op(0x7c6, self.read(frame + 0x88))
        return out

    def start_scheduler(self):
        vector = self.csr_op(0x305)
        if vector & 3:
            self.call(ASSERT, 0x70a1d864, 0x70a1d834, 0x105)
        self.call(SETUP_TIMER)
        self.csr_op(0x304, self.csr[0x304] | 0x880)
        return self.start_first()

    # Driver.
    def run(self):
        rows = []
        for op in self.c['operations']:
            self.actions.append('op:' + op['name'])
            stopped, registers = None, None
            try:
                registers = self.operation(op)
            except Stopped as stop:
                stopped = stop.label
            if registers is not None:
                stopped = 'mret'
            row = dict(stopped=stopped, csrs={str(n): self.csr[n] for n in CSRS})
            if op['registers'] and stopped == 'mret':
                regs, fregs = registers
                row['registers'] = {name: word(regs[name]) for name in X[1:]}
                row['fregisters'] = fregs
            row['snapshot'] = {str(a): self.snapshot(a, n) for a, n in self.c['snapshot']}
            rows.append(row)
            if stopped:
                break
        return dict(actions=self.actions, rows=rows)

    def snapshot(self, address, size):
        return bytes(self.read(address + i, 1) for i in range(size)).hex()

    def operation(self, op):
        kind, args = op['name'].split('#')[0], op['args']
        if kind == 'register':
            self.register(*args)
        elif kind == 'enable':
            self.enable(args[0])
        elif kind == 'disable':
            self.enable(args[0], False)
        elif kind == 'mask':
            self.mask_all()
        elif kind == 'restore':
            self.restore_all()
        elif kind == 'init':
            self.irq_init()
        elif kind == 'deinit':
            self.irq_deinit()
        elif kind == 'trap':
            out, _ = self.trap_entry()
            return out
        elif kind == 'start':
            return self.start_first()
        elif kind == 'scheduler':
            return self.start_scheduler()
        else:
            raise ValueError('operation')
        return None


class Stopped(Exception):
    def __init__(self, label):
        super().__init__(label)
        self.label = label


def contract(case):
    if case['scope'] not in ('api', 'trap', 'start'):
        raise ValueError('trap/irq scope')
    if not 1 <= len(case['operations']) <= 12 or len(case['claims']) > 4:
        raise ValueError('bounded operations')
    return Model(case).run()


# Vector construction.
def words(*values):
    return b''.join(struct.pack('<I', v & MASK) for v in values).hex()


def frame_bytes(base, seed):
    """Authored resumable frame for a task whose saved stack pointer is base."""
    data = bytearray(FRAME)
    for index, name in enumerate(X):
        if index:
            struct.pack_into('<I', data, 4 * index, (seed + 0x01010101 * index) & MASK)
    struct.pack_into('<I', data, 8, base)
    struct.pack_into('<IIII', data, 0x80, 0x1880, CODE_AREA + 0x40, 0x21, seed ^ 0x5a5a)
    for i in range(32):
        struct.pack_into('<Q', data, 0x90 + 8 * i, (seed << 32 | 0x3f800000 + i) & (2 ** 64 - 1))
    struct.pack_into('<I', data, 0x190, 0x60)
    return data.hex()


def external_table(entries):
    data = bytearray()
    for irq in range(EXTERNAL_COUNT):
        handler, argument, enabled, priority = entries.get(irq, (DEFAULT_HANDLER, 0, 0, 0))
        data += struct.pack('<IIII', handler, argument, enabled, priority)
    return data.hex()


def base_case(name, scope, operations, **changes):
    case = dict(
        name='main_trap_irq_' + name, scope=scope, claims=[], supplied_reads=[PLIC_CLAIM],
        quiet=[list(q) for q in QUIET], csr_allowed=list(CSRS),
        ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): v for n, v in zip(CSRS, (0x20, 0x1808, 0x888, 0x80d35e00, 0x51515151,
                                                 CODE_AREA, 0x8000000b, 0x21, 0x81100000))},
        registers={'sp': HARNESS_STACK}, fregisters={}, stubs={}, stops={},
        snapshot=[[PLIC_ENABLE, 12], [SAVED_MIE, 8]], operations=operations,
        memory=[[SAVED_MIE, words(0x13579bdf, 0)], [TRACE_FLAG, '00'],
                [PLIC_ENABLE, words(0x01000000, 0, 0x00040000)],
                [EXTERNAL_TABLE, external_table({})]])
    case.update(changes)
    return case


def op(name, *args, registers=False, entry=None, call=True):
    targets = dict(register=REGISTER, enable=ENABLE, disable=DISABLE, mask=MASK_ALL, restore=RESTORE_ALL,
                   init=IRQ_INIT, deinit=IRQ_DEINIT, trap=TRAP_ENTRY, start=START_FIRST,
                   scheduler=START_SCHEDULER)
    return dict(name=name, entry=entry or targets[name.split('#')[0]], call=call, args=list(args),
                registers=registers)


def trap_case(name, cause, claims=(), table=None, flag=0, in_trap=0, stubs=None, switch_to=None,
              tick=0, compare=(0x00001000, 0x7), epc_half=0x0001, a7=0x1717, extra_memory=(), core=None):
    regs = {name_: (0x11110000 + 0x101 * i) & MASK for i, name_ in enumerate(X) if i}
    regs['sp'] = TASK_A_STACK
    regs['a7'] = a7
    fregs = {f: '%016x' % (0x4000000000000000 | (i * 0x0101010101)) for i, f in enumerate(F)}
    stub = {str(MEMCPY): dict(kind='memcpy', args=3), str(MEMSET): dict(kind='memset', args=3),
            str(DEFAULT_HANDLER): dict(kind='stop', label='default_handler', args=1),
            '0': dict(kind='stop', label='null_vector', args=1),
            str(TICK): dict(kind='return', value=tick, args=0),
            str(SWITCH): dict(kind='switch', args=0)}
    for vector in EXCEPTION_VECTORS[:-1]:
        stub[str(vector)] = dict(kind='return', args=2)
    if switch_to:
        stub[str(SWITCH)].update(current=switch_to, current_address=CURRENT)
    for address, value in (stubs or {}).items():
        stub[str(address)] = value
    memory = [
        [SAVED_MIE, words(OUT_OF_TABLE_HANDLER, in_trap)], [TRACE_FLAG, '%02x' % flag],
        [CURRENT, words(TCB_A)], [TCB_A, words(0x81101000)], [TCB_A + 0x34, b'task-a-name-padding'.hex()],
        [TCB_B, words(TASK_B_FRAME)], [TCB_B + 0x34, b'task-b-name-padding'.hex()],
        [TASK_B_FRAME, frame_bytes(TASK_B_FRAME, 0x6b000000)],
        [EXTERNAL_TABLE, external_table(table or {})], [NEXT_COMPARE, words(*compare)],
        [CODE_AREA, words(epc_half)], [TRACE, words(*[0x0c0c0c0c] * 10)],
        [PLIC_ENABLE, words(0, 0, 0)], [TASK_A_STACK - 0x200, 'a5' * 0x200]] + [list(m) for m in extra_memory]
    if core:
        memory.append([CORE_TABLE + 16 * core[0], words(core[1], core[2])])
    csrs = {str(n): v for n, v in zip(CSRS, (0x41, 0x1880, 0x888, TRAP_ENTRY, 0x5c5c5c5c, CODE_AREA, cause,
                                             0x21, 0x81100000))}
    return base_case(name, 'trap', [op('trap', registers=True, call=False)], claims=list(claims),
                     registers=regs, fregisters=fregs, stubs=stub, csrs=csrs,
                     stops={str(TRAP_MRET): 'mret'}, memory=memory,
                     snapshot=[[TASK_A_STACK - FRAME, FRAME], [TRACE, 0x28], [IN_TRAP, 4], [TCB_A, 4]])


def native_vectors():
    cases = []

    def add(case):
        case['expected'] = contract(case)
        cases.append(case)

    api_stubs = {str(MEMSET): dict(kind='memset', args=3)}
    dma = ((0x16, 0x93000000), (0x19, 0x93040000), (0x1c, 0x93080000), (0x12, 0x92000000))
    add(base_case('init', 'api', [op('init')], stubs=api_stubs,
                  snapshot=[[PLIC_ENABLE, 12], [PLIC_PRIORITY, 0x150], [PLIC_THRESHOLD, 4]],
                  memory=base_case('x', 'api', [])['memory'] + [[PLIC_PRIORITY, words(*[7] * 84)],
                                                               [PLIC_THRESHOLD, words(5)]]))
    add(base_case('deinit', 'api', [op('deinit')], stubs=api_stubs,
                  snapshot=[[PLIC_ENABLE, 12], [PLIC_PRIORITY, 8], [PLIC_THRESHOLD, 4]],
                  memory=base_case('x', 'api', [])['memory'] + [[PLIC_PRIORITY, words(*[7] * 84)],
                                                               [PLIC_THRESHOLD, words(5)]]))
    dma_ops = []
    for irq, argument in dma:
        dma_ops += [op('register#%x' % irq, irq, 0x702a041c, argument), op('enable#%x' % irq, irq)]
    add(base_case('dma_registration_sequence', 'api', dma_ops,
                  memory=base_case('x', 'api', [])['memory'] + [[PLIC_PRIORITY, words(*[0] * 84)]],
                  snapshot=[[PLIC_ENABLE, 12], [PLIC_PRIORITY + 0x48, 0x2c]]))
    for name, irq in (('external_last', 0x52), ('external_out_of_range', 0x53), ('external_high_bits', 0x20000016),
                      ('local_first', 0x10000000), ('local_last', 0x1000000f), ('local_out_of_range', 0x10000010),
                      ('local_high_bits', 0xf0000003), ('local_large', 0x10000016)):
        add(base_case('register_' + name, 'api', [op('register', irq, 0x70aa0000, 0x5aa50000)],
                      memory=base_case('x', 'api', [])['memory'] + [[PLIC_PRIORITY, words(*[0] * 84)]],
                      snapshot=[[PLIC_ENABLE, 12], [CORE_TABLE + 0x100, 0x100]]))
    for name, irq in (('external_word0', 0x9), ('external_word2', 0x51), ('external_last', 0x52),
                      ('external_out_of_range', 0x53), ('local_timer_bit', 0x10000003),
                      ('local_last_registerable', 0x1000000f), ('local_sixteen', 0x10000010),
                      ('local_out_of_range', 0x10000011)):
        add(base_case('enable_' + name, 'api', [op('enable', irq)]))
        add(base_case('disable_' + name, 'api', [op('disable', irq)]))
    table = {0x16: (0x702a041c, 0x93000000, 1, 1), 0x2a: (0x70293d50, 0x98005000, 1, 6),
             0x40: (0x70aa0000, 0, 0, 3), 0x52: (0x70aa0004, 9, 2, 0xffffffff)}
    add(base_case('mask_restore', 'api', [op('mask'), op('restore')],
                  memory=base_case('x', 'api', [])['memory'] + [[EXTERNAL_TABLE, external_table(table)],
                                                               [PLIC_ENABLE, words(0, 0, 0)],
                                                               [PLIC_PRIORITY, words(*[0] * 84)]],
                  snapshot=[[PLIC_ENABLE, 12], [PLIC_PRIORITY + 0x58, 4], [PLIC_PRIORITY + 0xa8, 4],
                            [PLIC_PRIORITY + 0x100, 4], [PLIC_PRIORITY + 0x148, 4], [SAVED_MIE, 4]]))
    add(base_case('restore_without_mask', 'api', [op('restore')]))

    dma_handler = {0x702a041c: dict(kind='return', args=1)}
    dma_table = {0x16: (0x702a041c, 0x93000000, 1, 1)}
    add(trap_case('external_dma', 0x8000000b, claims=[0x16], table=dma_table, stubs=dma_handler))
    add(trap_case('external_dma_traced', 0x8000000b, claims=[0x16], table=dma_table, stubs=dma_handler, flag=1))
    add(trap_case('external_unregistered', 0x8000000b, claims=[0x2a]))
    add(trap_case('external_claim_zero', 0x8000000b, claims=[0]))
    add(trap_case('external_claim_past_table', 0x8000000b, claims=[0x53],
                  stubs={OUT_OF_TABLE_HANDLER: dict(kind='return', args=1)}))
    add(trap_case('external_switch', 0x8000000b, claims=[0x16], table=dma_table,
                  stubs={0x702a041c: dict(kind='switch', args=1, current=TCB_B, current_address=CURRENT)}))
    add(trap_case('external_nested', 0x8000000b, claims=[0x16], table=dma_table, stubs=dma_handler, in_trap=1))
    add(trap_case('timer_no_switch', 0x80000007))
    add(trap_case('timer_switch', 0x80000007, tick=1, switch_to=TCB_B))
    add(trap_case('timer_switch_traced', 0x80000007, tick=1, switch_to=TCB_B, flag=1))
    add(trap_case('timer_compare_carry', 0x80000007, compare=(0xfffffe00, 0x7)))
    add(trap_case('software', 0x80000003))
    add(trap_case('local_registered', 0x80000013, core=(19, 0x70aa0010, 0x1234),
                  stubs={0x70aa0010: dict(kind='return', args=1)}))
    add(trap_case('local_unregistered', 0x80000010))
    add(trap_case('interrupt_code_zero', 0x80000000))
    add(trap_case('yield_ecall', 11, a7=SYSCALL_YIELD, epc_half=0x0073))
    add(trap_case('yield_ecall_switch', 11, a7=SYSCALL_YIELD, epc_half=0x0073, switch_to=TCB_B))
    add(trap_case('yield_ecall_traced', 11, a7=SYSCALL_YIELD, epc_half=0x0073, switch_to=TCB_B, flag=1))
    add(trap_case('ecall_other_number', 11, a7=0xf0000001, epc_half=0x0073))
    add(trap_case('illegal_compressed', 2, epc_half=0x0001))
    add(trap_case('illegal_standard', 2, epc_half=0x1003))
    add(trap_case('breakpoint', 3, epc_half=0x9002))
    add(trap_case('load_fault', 5, epc_half=0x4503))
    add(trap_case('exception_past_table', 12))

    start_regs = {'sp': HARNESS_STACK}
    for name, vector, csrs_extra in (('start_first_task', 0x00000000, {}),):
        add(base_case(name, 'start', [op('start', registers=True)], registers=start_regs,
                      memory=[[CURRENT, words(TCB_B)], [TCB_B, words(TASK_B_FRAME)],
                              [TASK_B_FRAME, frame_bytes(TASK_B_FRAME, 0x6b000000)]],
                      stops={str(START_MRET): 'mret'}, snapshot=[]))
    for name, vector in (('scheduler_direct_vector', 0x80d35e00), ('scheduler_vectored_vector', 0x80d35e01),
                         ('scheduler_mode_bits_two', 0x80d35e02)):
        csrs = {str(n): v for n, v in zip(CSRS, (0x20, 0x1808, 0x8, vector, 0x51515151, CODE_AREA, 0x8000000b,
                                                 0x21, 0x81100000))}
        add(base_case(name, 'start', [op('scheduler', registers=True)], registers=start_regs, csrs=csrs,
                      stubs={str(SETUP_TIMER): dict(kind='return', args=0),
                             str(ASSERT): dict(kind='stop', label='assert', args=3)},
                      memory=[[CURRENT, words(TCB_B)], [TCB_B, words(TASK_B_FRAME)],
                              [TASK_B_FRAME, frame_bytes(TASK_B_FRAME, 0x6b000000)]],
                      stops={str(START_MRET): 'mret'}, snapshot=[]))
    return dict(schema=1, bound_per_case=BOUND, guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA],
                cases=cases)


# Static evidence: independent raw decoder for registration call arguments.
def sx(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def decode(memory, pc):
    half = struct.unpack('<H', memory.read(pc, 2))[0]
    if half & 3 == 3:
        w = struct.unpack('<I', memory.read(pc, 4))[0]
        opcode, rd, f3, rs1 = w & 0x7f, (w >> 7) & 31, (w >> 12) & 7, (w >> 15) & 31
        if opcode == 0x17:
            return 4, ('auipc', rd, None, w & 0xfffff000)
        if opcode == 0x37:
            return 4, ('lui', rd, None, w & 0xfffff000)
        if opcode == 0x13 and f3 == 0:
            return 4, ('addi', rd, rs1, sx(w >> 20, 12))
        if opcode == 0x67:
            return 4, ('jalr', rd, rs1, sx(w >> 20, 12))
        if opcode in (0x6f, 0x63):
            return 4, ('branch', 1 if opcode == 0x6f else None, None, None)
        if opcode == 0x23:
            return 4, ('store', None, None, None)
        return 4, ('other', rd if opcode in (0x03, 0x13, 0x33, 0x73) else None, None, None)
    quadrant, f3 = half & 3, half >> 13
    rd = (half >> 7) & 31
    if quadrant == 1 and f3 == 3 and rd not in (0, 2):
        return 2, ('lui', rd, None, sx((((half >> 12) & 1) << 17) | (((half >> 2) & 31) << 12), 18) & MASK)
    if quadrant == 1 and f3 == 0:
        return 2, ('addi', rd, rd, sx((((half >> 12) & 1) << 5) | ((half >> 2) & 31), 6))
    if quadrant == 1 and f3 == 2:
        return 2, ('li', rd, None, sx((((half >> 12) & 1) << 5) | ((half >> 2) & 31), 6))
    if quadrant == 2 and f3 == 4:
        rs2 = (half >> 2) & 31
        if rs2 == 0:
            return 2, ('jalr', 1 if (half >> 12) & 1 else 0, rd, 0)
        return 2, ('mv' if not (half >> 12) & 1 else 'other', rd, rs2 if not (half >> 12) & 1 else None, None)
    if quadrant == 1 and f3 in (1, 5, 6, 7):
        return 2, ('branch', 1 if f3 == 1 else None, None, None)
    if quadrant == 0 and f3 == 6 or quadrant == 2 and f3 == 6:
        return 2, ('store', None, None, None)
    if quadrant == 0:
        return 2, ('other', 8 + ((half >> 2) & 7), None, None)
    return 2, ('other', rd if rd else None, None, None)


def call_target(memory, site):
    """Target of an auipc/jalr far call beginning at site, else None."""
    n, a = decode(memory, site)
    m, b = decode(memory, site + n)
    if a[0] == 'auipc' and b[0] == 'jalr' and b[2] == a[1] and b[1] == 1:
        return (site + a[3] + b[3]) & MASK
    return None


def arguments(memory, site, window=0x40):
    """Constant a0-a2 at a call, from the longest linear sweep that lands on site."""
    for start in range(site - window, site, 2):
        known, pc, ok = {0: 0}, start, True
        while pc < site:
            try:
                n, (kind, rd, rs1, imm) = decode(memory, pc)
            except struct.error:
                ok = False
                break
            if kind == 'branch':
                known.clear() if rd else None
            elif kind == 'auipc':
                known[rd] = (pc + imm) & MASK
            elif kind in ('lui', 'li'):
                known[rd] = imm & MASK
            elif kind == 'addi':
                if rs1 in known:
                    known[rd] = (known[rs1] + imm) & MASK
                else:
                    known.pop(rd, None)
            elif kind == 'mv':
                if rs1 in known:
                    known[rd] = known[rs1]
                else:
                    known.pop(rd, None)
            elif kind == 'jalr':
                known.clear()
            elif rd is not None:
                known.pop(rd, None)
            known[0] = 0
            pc += n
        if ok and pc == site:
            return tuple(known.get(r) for r in (10, 11, 12))
    return (None, None, None)


def registration_sites(memory):
    found = []
    lo, hi = 0x70160000, 0x70160000 + 0xc83214
    for pc in range(lo, hi - 8, 2):
        half = struct.unpack('<H', memory.read(pc, 2))[0]
        if half & 0xfff != 0x097:  # auipc ra
            continue
        if call_target(memory, pc) == REGISTER:
            found.append(pc + 4)
    return found


def direct_registration_sites(memory):
    """jal/c.jal/c.j sites in the RAM code copy whose target is the registration routine."""
    found = []
    lo, hi = COPY['destination'], COPY['destination'] + COPY['size']
    for pc in range(lo, hi - 4, 2):
        half = struct.unpack('<H', memory.read(pc, 2))[0]
        target = None
        if half & 3 == 3:
            w = struct.unpack('<I', memory.read(pc, 4))[0]
            if w & 0x7f == 0x6f:
                imm = (((w >> 31) & 1) << 20 | ((w >> 12) & 0xff) << 12 | ((w >> 20) & 1) << 11
                       | ((w >> 21) & 0x3ff) << 1)
                target = (pc + sx(imm, 21)) & MASK
        elif half & 3 == 1 and half >> 13 in (1, 5):
            imm = (((half >> 12) & 1) << 11 | ((half >> 8) & 1) << 10 | ((half >> 9) & 3) << 8
                   | ((half >> 6) & 1) << 7 | ((half >> 7) & 1) << 6 | ((half >> 2) & 1) << 5
                   | ((half >> 11) & 1) << 4 | ((half >> 3) & 7) << 1)
            target = (pc + sx(imm, 12)) & MASK
        if target == REGISTER:
            found.append(pc)
    return found


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in CODE + DATA:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    copies = [r for r in memory.regions if r['kind'] == 'copy' and r['destination'] == COPY['destination']]
    if len(copies) != 1 or copies[0]['source'] != COPY['source'] or copies[0]['size'] != COPY['size']:
        raise ValueError('RAM code copy differs')
    for address, size, _ in CODE:
        if address >= COPY['destination']:
            source = COPY['source'] + address - COPY['destination']
            if memory.data[source - 0x70160000:source - 0x70160000 + size] != memory.read(address, size):
                raise ValueError('copied code differs from its load image')
    core = {i: struct.unpack_from('<I', memory.read(CORE_TABLE + 16 * i, 4))[0] for i in range(32)}
    if {i: v for i, v in core.items() if v} != CORE_VECTORS:
        raise ValueError('core vector table')
    if any(struct.unpack('<III', memory.read(CORE_TABLE + 16 * i + 4, 12)) != (0, 0, 0) for i in range(32)):
        raise ValueError('core vector arguments')
    if struct.unpack('<12I', memory.read(EXCEPTION_TABLE, 0x30)) != EXCEPTION_VECTORS:
        raise ValueError('exception vector table')
    if struct.unpack('<I', memory.read(ISR_STACK_WORD, 4))[0] != ISR_STACK:
        raise ValueError('ISR stack top')
    for address, text in STRINGS:
        if memory.read(address, len(text) + 1) != text + b'\0':
            raise ValueError('FreeRTOS string')
    recovered = tuple((site,) + arguments(memory, site - 4) for site in registration_sites(memory))
    if recovered != REGISTRATIONS:
        raise ValueError('registration call sites differ: %r' % (recovered,))
    direct = tuple((site,) + arguments(memory, site) for site in direct_registration_sites(memory))
    if direct != DIRECT_REGISTRATIONS:
        raise ValueError('direct registration call sites differ: %r' % (direct,))
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    for row, case in zip(report['cases'], vector_doc['cases']):
        if row['name'] != case['name'] or row['observed'] != case['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + case['name'])
    return dict(
        main_sha256=MAIN_HASH, vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        ram_code_copy={k: f'{v:#x}' for k, v in COPY.items()},
        core_vectors={str(k): f'{v:#010x}' for k, v in CORE_VECTORS.items()},
        exception_vectors=[f'{v:#010x}' for v in EXCEPTION_VECTORS],
        isr_stack_top=f'{ISR_STACK:#010x}',
        freertos_strings={f'{a:#010x}': t.decode() for a, t in STRINGS},
        registration_sites=[dict(site=f'{s:#010x}', irq=None if i is None else f'{i:#x}',
                                 handler=f'{h:#010x}', argument=None if a is None else f'{a:#010x}')
                            for s, i, h, a in REGISTRATIONS],
        direct_registration_sites=[dict(site=f'{s:#010x}', irq=f'{i:#x}', handler=f'{h:#010x}',
                                        argument=f'{a:#010x}') for s, i, h, a in DIRECT_REGISTRATIONS],
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Original trap entry, C trap handler, core/PLIC dispatch, PLIC API, IRQ init/deinit, timer, '
            'exception/syscall/yield and first-task/scheduler-start bodies execute in an emulator over '
            'authored memory, CSRs, registers and PLIC claim values; no hardware interrupt is delivered.',
            'xTaskIncrementTick, vTaskSwitchContext, vPortSetupTimerInterrupt, configASSERT, memcpy, memset, '
            'device interrupt handlers and non-syscall exception handlers are supplied. Default-handler, '
            'null-vector and assert stops are harness stops before an infinite loop, a jump to address zero '
            'or an assertion body; mret is not executed.',
            'Andes CSR 0x7c6/0x7c7 names, PLIC register roles and timer units are working interpretations '
            'of observed accesses. Interrupt preemption, priority/threshold arbitration, nesting timing, '
            'live scheduling and physical timer frequency remain unproved.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', nargs='?')
    parser.add_argument('--vectors-output', type=Path)
    parser.add_argument('--vectors', type=Path)
    parser.add_argument('--validation', type=Path)
    args = parser.parse_args()
    try:
        if args.vectors_output:
            args.vectors_output.write_text(json.dumps(native_vectors(), indent=2, sort_keys=True) + '\n')
            return
        if not all((args.archive, args.vectors, args.validation)):
            parser.error('need archive, --vectors and --validation')
        with zipfile.ZipFile(args.archive) as archive:
            result = evidence(archive, args.vectors, args.validation)
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect main trap/IRQ paths: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
