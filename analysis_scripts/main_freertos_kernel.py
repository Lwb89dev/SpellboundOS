#!/usr/bin/env python3
"""Main FreeRTOS kernel: tick, context selection, timer setup, task creation.

The model below independently describes the original main-image FreeRTOS
bodies that ValidateMainFreertosKernel.java executes natively over authored
state: ``xTaskIncrementTick``, ``vTaskSwitchContext``, the list primitives,
``prvResetNextTaskUnblockTime``, ``vPortSetupTimerInterrupt``, the source-14
interrupt acknowledgement, the run-time counter, ``pxPortInitialiseStack``,
``prvInitialiseNewTask``, ``prvAddNewTaskToReadyList`` with its critical
section, ``xTaskCreateStatic`` and the libgcc ``__clzsi2`` used for priority
selection.  Selected cases join these bodies to the original trap entry,
timer handler, first-task start and scheduler start already covered by
main_trap_irq.  Nothing here executes vendor code.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_trap_irq as trap
    from .main_object_lifecycle import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    import main_trap_irq as trap
    from main_object_lifecycle import image_memory
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
MASK64 = (1 << 64) - 1
BOUND = 5000
END = trap.END

# Original RAM routines (startup copy .copy2) and image routines.
LIST_INIT = 0x80d37d82          # vListInitialise
ITEM_INIT = 0x80d37d96          # vListInitialiseItem
INSERT_END = 0x80d37d9c         # vListInsertEnd
REMOVE = 0x80d37de2             # uxListRemove
TASK_EXIT = 0x80d37e02          # initial task return address: vTaskDelete(NULL)
SOURCE14 = 0x80d37e08           # handler registered by vPortSetupTimerInterrupt
SETUP_TIMER = 0x80d37e14        # vPortSetupTimerInterrupt
INIT_STACK = 0x80d37e66         # pxPortInitialiseStack
RUNTIME_INIT = 0x80d37f8c       # run-time counter base capture
RUNTIME_READ = 0x80d37fa6       # run-time counter value
TICK_HOOK = 0x80d364a6          # empty application tick hook
RESET_UNBLOCK = 0x80d39378      # prvResetNextTaskUnblockTime
INIT_TASK = 0x80d394f6          # prvInitialiseNewTask
TICK = 0x80d3974e               # xTaskIncrementTick
SWITCH = 0x80d398d6             # vTaskSwitchContext
ENTER = 0x80d3a062              # vTaskEnterCritical
EXIT = 0x80d3a0ae               # vTaskExitCritical
ADD_READY = 0x80d3a0fa          # prvAddNewTaskToReadyList
CREATE_STATIC = 0x80d3a234      # xTaskCreateStatic
ACK = 0x80d42c68                # peripheral acknowledgement used by SOURCE14
MTIME_READ = 0x80d4548c         # consistent 64-bit mtime read
CLZ = 0x709450d0                # libgcc __clzsi2
CLZ_TABLE = 0x709babf8

# Supplied callees.
ASSERT = trap.ASSERT
MEMSET = trap.MEMSET
DIAG = 0x80d33720               # critical-section diagnostic body (covered by main_cache_control)
DELETE = 0x80d3a45c             # vTaskDelete
OVERFLOW_HOOK = 0x701645a0      # vApplicationStackOverflowHook
YIELD = trap.YIELD_WRAPPER      # ecall yield wrapper

# Kernel globals.
RUN_BASE = 0x80c07de0
NEXT_COMPARE = trap.NEXT_COMPARE
TOTAL = 0x80c07e30              # ulTotalRunTime (64-bit)
SWITCHED = 0x80c07e38           # ulTaskSwitchedInTime (64-bit)
SUSPENDED = 0x80c07e40          # uxSchedulerSuspended
NEXT_UNBLOCK = 0x80c07e48       # xNextTaskUnblockTime
TASK_NUMBER = 0x80c07e4c        # uxTaskNumber
OVERFLOWS = 0x80c07e50          # xNumOfOverflows
YIELD_PENDING = 0x80c07e54      # xYieldPending
PENDED = 0x80c07e58             # xPendedTicks
RUNNING = 0x80c07e5c            # xSchedulerRunning
TOP_READY = 0x80c07e60          # uxTopReadyPriority bitmap
TICK_COUNT = 0x80c07e64         # xTickCount
NUM_TASKS = 0x80c07e68          # uxCurrentNumberOfTasks
ERRNO = 0x80c07e6c              # FreeRTOS_errno
SUSPENDED_LIST = 0x80c07e70
TERMINATION = 0x80c07e88
PENDING_READY = 0x80c07e9c
OVERFLOW_PTR = 0x80c07eb0       # pxOverflowDelayedTaskList
DELAYED_PTR = 0x80c07eb4        # pxDelayedTaskList
DELAYED2 = 0x80c07eb8
DELAYED1 = 0x80c07ecc
READY = 0x80c07ee0              # pxReadyTasksLists[10], stride 0x14
CURRENT = trap.CURRENT          # pxCurrentTCB
KBASE, KSIZE = 0x80c07de0, 0x1cc
IMPURE = 0x70f884f8             # newlib _impure_ptr (initialized .data)
SOURCE14_OBJECT = 0x80c000b8
SOURCE14_ORIGINAL = 0x91005010
ACK_REGISTER = 0x91005000
MTIME_LO, MTIME_HI = 0xe6000000, 0xe6000004
MTIMECMP = trap.MTIMECMP
REENT_LOCALE = 0x709c4a58
PRIORITIES = 10
TCB_SIZE = 0x4c0
FRAME = trap.FRAME
STACK_FILL = 0xa5a5a5a5

TASKS_FILE = 0x70a1dcf4
ASSERTS = dict(overflow=(0x70a1de20, TASKS_FILE, 0xb64), empty=(0x70a1de4c, TASKS_FILE, 0xcc3),
               stack=(0x70a1df44, TASKS_FILE, 0x269), tcb=(0x70a1df5c, TASKS_FILE, 0x26a))

CODE = (
    (LIST_INIT, 0x14, '57c29f724d0e61a7b1a69f58304fb6c0ca82649a2a272ff04f9859a9ef6fac19'),
    (ITEM_INIT, 0x6, '7a2f3d6215d921e8c22ab19775d93214c4c9c36c9ba02b6a1027e037e0611366'),
    (INSERT_END, 0x18, '0703c53cf798e776b7e4752e06cbad007706d87a093eecf143567d874d1425fc'),
    (REMOVE, 0x20, '6e61e586c7c1bff0c209e24707a0f8977304432412d8e1000fae737f37dbcfd1'),
    (TASK_EXIT, 0x6, 'ee39e2f8998c0a6d0b2f00a229a28080499c5f33bda8d91d9aa817403a993860'),
    (SOURCE14, 0xc, '5d2e78db1ebdb08ef12bc9371ccd0a4531868f43fb84371e8e6692ee599fcfa3'),
    (SETUP_TIMER, 0x52, '936430accc0369f177732ef790dc8da0b99535bf5ff7c81d92fed4dd0889420e'),
    (INIT_STACK, 0x64, 'bd669a7a7bb187119120ba162f6bbccdb344b5a3cdfcd566edab719baca2aa70'),
    (RUNTIME_INIT, 0x1a, '162a78d1ac421dc175c622b837ecaf584c8975860169e109d63e6faff005e0bb'),
    (RUNTIME_READ, 0x28, '94056731039025d3edc539ab928750a8017944669f6a9a1aa5e67c5391fe65d3'),
    (TICK_HOOK, 0x2, '7529d4e6ceb037815e2664a7277abb404b02f0bf9ddbf5c11658f52448221cba'),
    (RESET_UNBLOCK, 0x24, '13c2a28e67d77f93c84281a6bc4006f659a885b074317d2004748b858394aaa4'),
    (INIT_TASK, 0x166, 'd9633dddd5577aed5a88797fcf68f97f6223014599f60ad79155b0b26f24d10f'),
    (TICK, 0x188, '8a0d59ff5ab83acf208c5c8cd5453f6d0603119e33410b43a45cf61277567eb8'),
    (SWITCH, 0x174, '324be20618af6d324d48ae164b04faa16752f736bb8f8325bab87678b394cf39'),
    (ENTER, 0x4c, 'bf1fa0a021f0ccbf98564e67217ef8a5a77ab295fcceb7becf900fcfc28b4386'),
    (EXIT, 0x4c, '1b2e411079a457949a60c7993eef11c2b2c9a639d4419326e91a2d3182a4b422'),
    (ADD_READY, 0x13a, 'b0c49bcceb28368696c7cf5e48145534a95b5a5921a282a351cc6e9b180fa281'),
    (CREATE_STATIC, 0xb8, '245a2004189f7aeb7d508d5ba89f092941ea904b9d8bebe64d18b5c85ea92745'),
    (MTIME_READ, 0x10, '2c382a27d9bca1971559cbc30388a4133dc7301cc45c9e65450139a2c6024989'),
    (ACK, 0x1a, 'ea9f301cf020702a9b4af2685c5a8d63c897305467decf61bc630ef9dfbf48c7'),
    (CLZ, 0x78, '44d147ebaceb6015ebe71f7bc2bb69c7147af854398958e0c2ee4df532286ba0'),
)
DATA = (
    (CLZ_TABLE, 0x100, '14a5d850c255623f9472e3c650abce0c78d32f0276b315b3a276a0462d97a1ac'),
    (SOURCE14_OBJECT, 0x4, 'df5ab279de32236d01f39fc2ceb43f8f7eba28847774d546704fe15a763fe24b'),
    (TASKS_FILE, 0x1c, 'be652418b4c6707dc4fa0f11c837886cd457b93ba4cacfe811968208e3eebd2a'),
)
# Direct jal/j call sites in the RAM copy that tie these bodies together.
CALL_SITES = (
    (0x80d37f18, SETUP_TIMER), (0x80d37f78, TICK), (0x80d37f82, SWITCH), (0x80d39632, INIT_STACK),
    (0x80d3a2c8, INIT_TASK), (0x80d3a2ce, ADD_READY), (0x80d3a382, RUNTIME_INIT), (0x80d3a386, trap.START_SCHEDULER),
    (0x80d3a430, INIT_TASK), (0x80d3a436, ADD_READY), (0x80d37e10, ACK),
)
CSRS = trap.CSRS
X, F = trap.X, trap.F
HARNESS_STACK = trap.HARNESS_STACK
HANDLE_SLOT = HARNESS_STACK - 0x30 + 8      # xTaskCreateStatic local xReturn
QUIET = ((0x81000000, 0x81002000), (0x81100000, 0x81102000), (0x81200000, 0x81202000),
         (0x80dffc00, 0x80e00000))
TCBS = tuple(0x81500000 + 0x800 * i for i in range(6))
STACKS = (0x81600000, 0x81601000, 0x81602000)
NAMES = 0x81700000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Stopped(trap.Stopped):
    pass


class Model(trap.Model):
    """Independent model of the original kernel bodies, emitting the runner's actions."""

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
        self.supplied = {int(k): list(v) for k, v in case['supplied'].items()}
        self.stubs = {int(k): v for k, v in case['stubs'].items()}
        self.quiet = [tuple(q) for q in case['quiet']]

    # Primitives.
    def original_byte(self, at):
        if CLZ_TABLE <= at < CLZ_TABLE + 0x100:
            return (at - CLZ_TABLE).bit_length()
        if SOURCE14_OBJECT <= at < SOURCE14_OBJECT + 4:
            return (SOURCE14_ORIGINAL >> (8 * (at - SOURCE14_OBJECT))) & 255
        return super().original_byte(at)

    def write(self, address, size, value, record=True):
        value &= (1 << (8 * size)) - 1
        address = word(address)
        for i in range(size):
            self.mem[address + i] = (value >> (8 * i)) & 255
        if record and not any(lo <= address < hi for lo, hi in self.quiet):
            self.actions.append(f'w:{address}:{size}:{value}')

    def read(self, address, size=4):
        return super().read(word(address), size)

    def supply(self, address):
        value = self.supplied[address].pop(0)
        self.actions.append(f'r:{address}:4:{value}')
        return value

    def claim(self):
        return self.supply(trap.PLIC_CLAIM)

    def call(self, address, *args):
        if address in self.stubs:
            return super().call(address, *args)
        actual = {TICK: self.tick, SWITCH: self.switch, SETUP_TIMER: self.setup_timer}
        if address in actual:
            return actual[address](*args)
        raise ValueError(f'unmodelled callee {address:#x}')

    def handler(self, address, argument):
        if address == SOURCE14 and address not in self.stubs:
            return self.source14(argument)
        return super().handler(address, argument)

    # List primitives.
    def list_init(self, lst):
        end = word(lst + 8)
        self.write(lst + 4, 4, end)
        self.write(lst + 8, 4, MASK)
        self.write(lst + 0xc, 4, end)
        self.write(lst + 0x10, 4, end)
        self.write(lst, 4, 0)

    def item_init(self, item):
        self.write(item + 0x10, 4, 0)

    def insert_end(self, lst, item):
        index = self.read(lst + 4)
        self.write(item + 4, 4, index)
        self.write(item + 8, 4, self.read(index + 8))
        self.write(self.read(index + 8) + 4, 4, item)
        self.write(index + 8, 4, item)
        count = self.read(lst)
        self.write(item + 0x10, 4, lst)
        self.write(lst, 4, count + 1)

    def remove(self, item):
        nxt, prev, lst = self.read(item + 4), self.read(item + 8), self.read(item + 0x10)
        self.write(nxt + 8, 4, prev)
        self.write(prev + 4, 4, nxt)
        if self.read(lst + 4) == item:
            self.write(lst + 4, 4, prev)
        count = self.read(lst)
        self.write(item + 0x10, 4, 0)
        self.write(lst, 4, count - 1)
        return self.read(lst)

    # Tick and context selection.
    def reset_next_unblock(self):
        if self.read(self.read(DELAYED_PTR)) == 0:
            self.write(NEXT_UNBLOCK, 4, MASK)
        else:
            self.write(NEXT_UNBLOCK, 4, self.read(self.read(self.read(DELAYED_PTR) + 0xc)))

    def tick(self):
        if self.read(SUSPENDED):
            self.write(PENDED, 4, self.read(PENDED) + 1)
            return 0                                   # the tick hook is a bare ret
        count = word(self.read(TICK_COUNT) + 1)
        self.write(TICK_COUNT, 4, count)
        if count == 0:
            if self.read(self.read(DELAYED_PTR)):
                self.call(ASSERT, *ASSERTS['overflow'])
            delayed, overflow = self.read(DELAYED_PTR), self.read(OVERFLOW_PTR)
            self.write(DELAYED_PTR, 4, overflow)
            self.write(OVERFLOW_PTR, 4, delayed)
            self.write(OVERFLOWS, 4, self.read(OVERFLOWS) + 1)
            self.reset_next_unblock()
        switch = 0
        if count >= self.read(NEXT_UNBLOCK):
            while True:
                if self.read(self.read(DELAYED_PTR)) == 0:
                    self.write(NEXT_UNBLOCK, 4, MASK)
                    break
                tcb = self.read(self.read(self.read(DELAYED_PTR) + 0xc) + 0xc)
                wake = self.read(tcb + 4)
                if count < wake:
                    self.write(NEXT_UNBLOCK, 4, wake)
                    break
                self.remove(tcb + 4)
                if self.read(tcb + 0x28):
                    self.remove(tcb + 0x18)
                priority = self.read(tcb + 0x2c)
                self.write(TOP_READY, 4, (1 << (priority & 31)) | self.read(TOP_READY))
                self.insert_end(word(READY + priority * 0x14), tcb + 4)
                if self.read(tcb + 0x2c) >= self.read(self.read(CURRENT) + 0x2c):
                    switch = 1
        if self.read(word(READY + self.read(self.read(CURRENT) + 0x2c) * 0x14)) > 1:
            switch = 1
        if self.read(YIELD_PENDING):
            switch = 1
        return switch

    def mtime(self):
        while True:
            high, low, again = self.supply(MTIME_HI), self.supply(MTIME_LO), self.supply(MTIME_HI)
            if again == high:
                return low, again

    def runtime_init(self):
        low, high = self.mtime()
        self.write(RUN_BASE, 4, low)
        self.write(RUN_BASE + 4, 4, high)
        return low, high

    def runtime_read(self):
        low, high = self.mtime()
        value = ((high << 32 | low) - self.read(RUN_BASE, 8)) & MASK64
        return value & MASK, value >> 32

    @staticmethod
    def clz(value):
        return 32 - value.bit_length()

    def switch(self):
        if self.read(SUSPENDED):
            self.write(YIELD_PENDING, 4, 1)
            return None
        self.write(YIELD_PENDING, 4, 0)
        low, high = self.runtime_read()
        self.write(TOTAL, 4, low)
        self.write(TOTAL + 4, 4, high)
        total, switched = self.read(TOTAL, 8), self.read(SWITCHED, 8)
        if total > switched:
            counter = self.read(CURRENT) + 0x80
            value = (self.read(counter, 8) - switched + total) & MASK64
            self.write(counter, 4, value & MASK)
            self.write(counter + 4, 4, value >> 32)
        self.write(SWITCHED, 4, self.read(TOTAL))
        self.write(SWITCHED + 4, 4, self.read(TOTAL + 4))
        stack = self.read(self.read(CURRENT) + 0x30)
        intact = self.read(stack) == STACK_FILL
        for i in range(1, 4):
            intact = intact and self.read(stack + 4 * i) == self.read(stack + 4 * (i - 1))
        if not intact:
            self.call(OVERFLOW_HOOK, self.read(CURRENT), self.read(CURRENT) + 0x34)
        current = self.read(CURRENT)
        self.write(current + 0x4b8, 4, self.read(ERRNO))
        top = word(0x1f - self.clz(self.read(TOP_READY)))
        lst = word(READY + top * 0x14)
        if self.read(lst) == 0:
            self.call(ASSERT, *ASSERTS['empty'])
        self.write(lst + 4, 4, self.read(self.read(lst + 4) + 4))
        if self.read(lst + 4) == word(lst + 8):
            self.write(lst + 4, 4, self.read(self.read(lst + 4) + 4))
        self.write(CURRENT, 4, self.read(self.read(lst + 4) + 0xc))
        self.write(ERRNO, 4, self.read(self.read(CURRENT) + 0x4b8))
        self.write(IMPURE, 4, self.read(CURRENT) + 0x88)
        return None

    # Port timer and source-14 acknowledgement.
    def setup_timer(self):
        low, high = self.mtime()
        compare = low + 1000
        self.write(MTIMECMP, 4, compare)
        self.write(MTIMECMP + 4, 4, high + (compare > MASK))
        nxt = low + 2000
        self.write(NEXT_COMPARE, 4, nxt)
        self.write(NEXT_COMPARE + 4, 4, high + (nxt > MASK))
        self.register(0xe, SOURCE14, 0)
        self.enable(0xe)
        return None

    def source14(self, _argument=None):
        self.write(ACK_REGISTER, 4, 2 if self.read(SOURCE14_OBJECT) == SOURCE14_ORIGINAL else 4)
        return None

    # Task creation.
    def init_stack(self, top, base, code, parameter):
        frame = word(top - FRAME)
        self.call(MEMSET, frame, 0, FRAME)
        self.write(frame + 4, 4, TASK_EXIT)
        self.write(frame + 0x28, 4, parameter)
        self.write(top - 0x118, 4, 0x7880)
        self.write(top - 0x114, 4, code)
        self.write(top - 0x10c, 4, base + FRAME)
        self.write(top - 0x110, 4, 0x21)
        return frame

    def init_task(self, code, name, depth, parameter, priority, created, tcb):
        self.call(MEMSET, self.read(tcb + 0x30), 0xa5, word(depth << 2))
        top = word(word(depth << 2) - 4 + self.read(tcb + 0x30)) & ~7
        self.write(tcb + 0x48, 4, top)
        self.write(tcb + 0x4c, 4, depth)
        if name:
            for i in range(0x14):
                value = self.read(name + i, 1)
                self.write(tcb + 0x34 + i, 1, value)
                if value == 0:
                    break
            self.write(tcb + 0x47, 1, 0)
        else:
            self.write(tcb + 0x34, 1, 0)
        priority = min(priority, PRIORITIES - 1)
        self.write(tcb + 0x2c, 4, priority)
        self.write(tcb + 0x5c, 4, priority)
        self.write(tcb + 0x60, 4, 0)
        self.item_init(tcb + 4)
        self.item_init(tcb + 0x18)
        self.write(tcb + 0x80, 4, 0)
        self.write(tcb + 0x84, 4, 0)
        self.write(tcb + 0x10, 4, tcb)
        self.write(tcb + 0x18, 4, PRIORITIES - priority)
        self.write(tcb + 0x24, 4, tcb)
        for offset in (0x50, 0x64, 0x68, 0x6c, 0x70, 0x74, 0x78, 0x4b0):
            self.write(tcb + offset, 4, 0)
        self.write(tcb + 0x4b4, 1, 0)
        self.call(MEMSET, tcb + 0x88, 0, 0x428)
        self.write(tcb + 0x8c, 4, tcb + 0x374)
        self.write(tcb + 0x90, 4, tcb + 0x3dc)
        self.write(tcb + 0x94, 4, tcb + 0x444)
        self.write(tcb + 0xbc, 4, REENT_LOCALE)
        self.write(tcb + 0x134, 4, 0)
        self.write(tcb + 0x130, 4, 1)
        self.write(tcb + 0x138, 4, 0xabcd330e)
        self.write(tcb + 0x13c, 4, 0xe66d1234)
        base = self.read(tcb + 0x30)
        self.write(tcb + 0x140, 4, 0x5deec)
        self.write(tcb + 0x144, 2, 0xb)
        self.write(tcb, 4, self.init_stack(top, base, code, parameter))
        if created:
            self.write(created, 4, tcb)

    def enter_critical(self):
        self.call(DIAG, 9, 3)
        self.csr_op(0x300, self.csr[0x300] & ~8)
        self.call(DIAG, 9, 1)
        if self.read(RUNNING):
            current = self.read(CURRENT)
            self.write(current + 0x50, 4, self.read(current + 0x50) + 1)
            if self.read(self.read(CURRENT) + 0x50) == 1:
                self.call(DIAG, 6, 1)

    def exit_critical(self):
        if not self.read(RUNNING) or not self.read(self.read(CURRENT) + 0x50):
            return
        current = self.read(CURRENT)
        self.write(current + 0x50, 4, self.read(current + 0x50) - 1)
        if self.read(self.read(CURRENT) + 0x50):
            return
        self.call(DIAG, 6, 0)
        self.call(DIAG, 9, 2)
        self.csr_op(0x300, self.csr[0x300] | 8)
        self.call(DIAG, 9, 0)

    def add_ready(self, tcb):
        self.enter_critical()
        self.write(NUM_TASKS, 4, self.read(NUM_TASKS) + 1)
        current = self.read(CURRENT)
        if current == 0:
            self.write(CURRENT, 4, tcb)
            if self.read(NUM_TASKS) == 1:
                for i in range(PRIORITIES):
                    self.list_init(READY + 0x14 * i)
                for lst in (DELAYED1, DELAYED2, PENDING_READY, TERMINATION, SUSPENDED_LIST):
                    self.list_init(lst)
                self.write(DELAYED_PTR, 4, DELAYED1)
                self.write(OVERFLOW_PTR, 4, DELAYED2)
        elif not self.read(RUNNING) and not self.read(tcb + 0x2c) < self.read(current + 0x2c):
            self.write(CURRENT, 4, tcb)
        number = self.read(TASK_NUMBER) + 1
        priority = self.read(tcb + 0x2c)
        self.write(TASK_NUMBER, 4, number)
        bitmap = self.read(TOP_READY)
        self.write(tcb + 0x54, 4, number)
        self.write(TOP_READY, 4, (1 << (priority & 31)) | bitmap)
        self.insert_end(word(READY + priority * 0x14), tcb + 4)
        self.exit_critical()
        if self.read(RUNNING) and self.read(self.read(CURRENT) + 0x2c) < self.read(tcb + 0x2c):
            self.call(YIELD)

    def create_static(self, code, name, depth, parameter, priority, stack, tcb):
        if stack == 0:
            self.call(ASSERT, *ASSERTS['stack'])
        if tcb == 0:
            self.call(ASSERT, *ASSERTS['tcb'])
        if tcb == 0 or stack == 0:
            return 0
        self.write(tcb + 0x4b5, 1, 2)
        self.write(tcb + 0x30, 4, stack)
        self.init_task(code, name, depth, parameter, priority, HANDLE_SLOT, tcb)
        self.add_ready(tcb)
        return self.read(HANDLE_SLOT)

    # Driver.
    def operation(self, op):
        kind, args = op['name'].split('#')[0], op['args']
        simple = dict(tick=self.tick, switch=self.switch, setup_timer=self.setup_timer, source14=self.source14,
                      runtime_init=self.runtime_init, runtime_read=self.runtime_read, init_stack=self.init_stack,
                      init_task=self.init_task, add_ready=self.add_ready, create_static=self.create_static,
                      list_init=self.list_init, insert_end=self.insert_end, remove=self.remove,
                      reset_unblock=self.reset_next_unblock, timer=self.timer)
        if kind == 'task_exit':
            self.call(DELETE, 0)
            return None
        if kind in ('trap', 'start', 'scheduler'):
            return super().operation(op)
        if kind == 'source14':
            return self.source14()
        return simple[kind](*args)

    def run(self):
        rows = []
        for op in self.c['operations']:
            self.actions.append('op:' + op['name'])
            stopped, result = None, None
            try:
                result = self.operation(op)
            except trap.Stopped as stop:
                stopped = stop.label
            kind = op['name'].split('#')[0]
            if kind in ('trap', 'start', 'scheduler') and stopped is None:
                stopped = 'mret'
            row = dict(stopped=stopped, csrs={str(n): self.csr[n] for n in CSRS})
            if stopped is None and op['result']:
                low, high = result if isinstance(result, tuple) else (result, None)
                row['a0'] = word(low)
                if op['result_high']:
                    row['a1'] = word(high)
            if op['registers'] and stopped == 'mret':
                regs, fregs = result
                row['registers'] = {name: word(regs[name]) for name in X[1:]}
                row['fregisters'] = fregs
            row['snapshot'] = {str(a): self.snapshot(a, n) for a, n in self.c['snapshot']}
            rows.append(row)
            if stopped:
                break
        return dict(actions=self.actions, rows=rows)


def contract(case):
    if case['scope'] not in ('port', 'tick', 'switch', 'create', 'connected'):
        raise ValueError('kernel scope')
    if not 1 <= len(case['operations']) <= 12 or sum(len(v) for v in case['supplied'].values()) > 24:
        raise ValueError('bounded operations')
    return Model(case).run()


# Vector construction.
def words(*values):
    return trap.words(*values)


class State:
    """Sparse authored memory for kernel globals, lists and task control blocks."""

    def __init__(self, current=0, priority_bitmap=0, tick=0, next_unblock=MASK, running=1, suspended=0):
        self.mem = {}
        self.put(KBASE, bytes(KSIZE))
        for lst in [READY + 0x14 * i for i in range(PRIORITIES)] + [DELAYED1, DELAYED2, PENDING_READY,
                                                                      TERMINATION, SUSPENDED_LIST]:
            self.link(lst, [])
        self.w32(DELAYED_PTR, DELAYED1)
        self.w32(OVERFLOW_PTR, DELAYED2)
        self.w32(CURRENT, current)
        self.w32(TOP_READY, priority_bitmap)
        self.w32(TICK_COUNT, tick)
        self.w32(NEXT_UNBLOCK, next_unblock)
        self.w32(RUNNING, running)
        self.w32(SUSPENDED, suspended)
        self.w32(ERRNO, 0x0e0e0e0e)
        self.w32(IMPURE, 0x70f87088)
        self.mem[trap.TRACE_FLAG] = 0

    def put(self, address, data):
        for i, b in enumerate(data):
            self.mem[address + i] = b

    def w32(self, address, value):
        self.put(address, struct.pack('<I', value & MASK))

    def w64(self, address, value):
        self.put(address, struct.pack('<Q', value & MASK64))

    def tcb(self, address, priority, stack, errno=0, runtime=0, name=b'task'):
        self.put(address, bytes(0x90))
        self.w32(address + 0x2c, priority)
        self.w32(address + 0x30, stack)
        self.put(address + 0x34, name[:0x13].ljust(0x14, b'\0'))
        self.w64(address + 0x80, runtime)
        self.w32(address + 0x4b8, errno)
        self.put(stack, struct.pack('<4I', *[STACK_FILL] * 4))
        return address

    def link(self, lst, items, index=None):
        """items: (item address, value, owner); owner None leaves it zero."""
        end = lst + 8
        nodes = [end] + [item for item, _, _ in items]
        self.w32(lst, len(items))
        self.w32(end, MASK)
        for k, node in enumerate(nodes):
            self.w32(node + 4, nodes[(k + 1) % len(nodes)])
            self.w32(node + 8, nodes[k - 1])
        for item, value, owner in items:
            self.w32(item, value)
            self.w32(item + 0xc, owner or 0)
            self.w32(item + 0x10, lst)
        self.w32(lst + 4, end if index is None else items[index][0])

    def ready(self, priority, tcbs, index=None):
        self.link(READY + 0x14 * priority, [(t + 4, 0, t) for t in tcbs], index)

    def delayed(self, entries, lst=DELAYED1, index=None):
        self.link(lst, [(t + 4, wake, t) for t, wake in entries], index)

    def event(self, tcb, lst, value=5):
        self.link(lst, [(tcb + 0x18, value, tcb)])

    def memory(self):
        out, run, start = [], bytearray(), None
        for address in sorted(self.mem):
            if start is not None and address == start + len(run):
                run.append(self.mem[address])
                continue
            if start is not None:
                out.append([start, run.hex()])
            start, run = address, bytearray([self.mem[address]])
        if start is not None:
            out.append([start, run.hex()])
        return out


RESULT_KINDS = ('tick', 'runtime_init', 'runtime_read', 'init_stack', 'create_static', 'remove')


def op(name, *args, entry=None, call=True, registers=False, result=True):
    targets = dict(tick=TICK, switch=SWITCH, setup_timer=SETUP_TIMER, source14=SOURCE14, runtime_init=RUNTIME_INIT,
                   runtime_read=RUNTIME_READ, init_stack=INIT_STACK, init_task=INIT_TASK, add_ready=ADD_READY,
                   create_static=CREATE_STATIC, list_init=LIST_INIT, insert_end=INSERT_END, remove=REMOVE,
                   reset_unblock=RESET_UNBLOCK, timer=trap.TIMER_HANDLER, task_exit=TASK_EXIT,
                   trap=trap.TRAP_ENTRY, start=trap.START_FIRST, scheduler=trap.START_SCHEDULER)
    kind = name.split('#')[0]
    return dict(name=name, entry=entry or targets[kind], call=call, args=list(args), registers=registers,
                result=result and kind in RESULT_KINDS, result_high=kind in ('runtime_init', 'runtime_read'))


def stubs(extra=None):
    out = {str(ASSERT): dict(kind='stop', label='assert', args=3),
           str(MEMSET): dict(kind='memset', args=3),
           str(DIAG): dict(kind='return', args=2),
           str(DELETE): dict(kind='stop', label='task_delete', args=1),
           str(OVERFLOW_HOOK): dict(kind='return', args=2),
           str(YIELD): dict(kind='stop', label='yield', args=0)}
    out.update({str(k): v for k, v in (extra or {}).items()})
    return out


def kernel_case(name, scope, operations, state, supplied=None, snapshot=(), csrs=None, registers=None,
                extra_stubs=None, stops=None):
    base_csrs = (0x20, 0x1888, 0x888, trap.TRAP_ENTRY, 0x51515151, trap.CODE_AREA, 0x8000000b, 0x21, 0x81100000)
    case = dict(
        name='main_freertos_kernel_' + name, scope=scope,
        supplied={str(k): list(v) for k, v in (supplied or {}).items()},
        quiet=[list(q) for q in QUIET], csr_allowed=list(CSRS),
        ranges=[[a, a + n] for a, n, _ in CODE + trap.CODE],
        csrs={str(n): v for n, v in zip(CSRS, csrs or base_csrs)},
        registers=registers or {'sp': HARNESS_STACK}, fregisters={},
        stubs=stubs(extra_stubs), stops=stops or {},
        snapshot=[list(s) for s in snapshot], operations=operations, memory=state.memory())
    return case


def mtime(*pairs, retry=None):
    """Supplied mtime words for consistent reads (high, low, high) of each pair."""
    hi, lo = [], []
    for low, high in pairs:
        if retry is not None:
            hi += [retry, high]
            lo.append(low ^ 0x5a5a)
            retry = None
        hi += [high, high]
        lo.append(low)
    return {MTIME_HI: hi, MTIME_LO: lo}


def merge(*maps):
    out = {}
    for m in maps:
        for k, v in m.items():
            out.setdefault(k, []).extend(v)
    return out


GLOBALS = [[KBASE, KSIZE]]


def tick_cases():
    a, b, c, d = TCBS[:4]
    s = STACKS
    cases = []

    def tick_case(name, state, snapshot=(), ops=None):
        cases.append(kernel_case('tick_' + name, 'tick', ops or [op('tick')], state,
                                 snapshot=GLOBALS + list(snapshot)))

    def base(tick=100, nxt=200, current=a, cur_prio=3, bitmap=1 << 3, **kw):
        st = State(current=current, priority_bitmap=bitmap, tick=tick, next_unblock=nxt, **kw)
        st.tcb(a, cur_prio, s[0], name=b'current')
        st.ready(cur_prio, [a])
        return st

    st = base(suspended=1)
    st.w32(PENDED, 4)
    tick_case('scheduler_suspended_pends', st)
    tick_case('before_unblock_time', base())
    st = base()
    st.tcb(b, 3, s[1], name=b'peer')
    st.ready(3, [a, b])
    tick_case('time_slice_equal_ready', st)
    st = base()
    st.w32(YIELD_PENDING, 1)
    tick_case('yield_pending', st)
    for label, prio in (('higher', 5), ('lower', 1), ('equal', 3)):
        st = base(nxt=101)
        st.tcb(b, prio, s[1], name=b'sleeper')
        st.delayed([(b, 101)])
        tick_case('wake_' + label, st, snapshot=[[b, 0x30]])
    st = base(nxt=101)
    st.tcb(b, 2, s[1], name=b'waiter')
    st.delayed([(b, 101)])
    st.w32(b + 0x18, 7)
    st.event(b, PENDING_READY)
    tick_case('wake_removes_event_item', st, snapshot=[[b, 0x30]])
    st = base(nxt=99)
    st.tcb(b, 4, s[1], name=b'first')
    st.tcb(c, 2, s[2], name=b'second')
    st.tcb(d, 6, s[2] + 0x100, name=b'later')
    st.delayed([(b, 99), (c, 101), (d, 150)])
    tick_case('wake_two_then_future_deadline', st, snapshot=[[b, 0x30], [c, 0x30], [d, 0x30]])
    st = base(nxt=101)
    st.tcb(b, 1, s[1], name=b'only')
    st.delayed([(b, 101)], index=0)
    tick_case('wake_moves_delayed_index', st, snapshot=[[b, 0x30]])
    tick_case('deadline_reached_empty_list', base(nxt=50))
    st = base(tick=MASK, nxt=MASK)
    st.tcb(b, 2, s[1], name=b'overflowed')
    st.delayed([(b, 40)], lst=DELAYED2)
    tick_case('wrap_swaps_lists_nonempty_overflow', st, snapshot=[[b, 0x30]])
    tick_case('wrap_swaps_lists_empty_overflow', base(tick=MASK, nxt=MASK))
    st = base(tick=MASK, nxt=MASK)
    st.tcb(b, 2, s[1], name=b'stale')
    st.delayed([(b, 0xfffffff0)])
    tick_case('wrap_with_pending_delayed_asserts', st)
    st = base(tick=0x7ffffffe, nxt=0x7fffffff)
    st.tcb(b, 3, s[1], name=b'boundary')
    st.delayed([(b, 0x80000000)])
    tick_case('unsigned_deadline_not_reached', st)
    return cases


def switch_cases():
    a, b, c, d = TCBS[:4]
    s = STACKS
    cases = []

    def switch_case(name, state, supplied=None, snapshot=(), ops=None):
        cases.append(kernel_case('switch_' + name, 'switch', ops or [op('switch')], state,
                                 supplied=supplied if supplied is not None else mtime((0x1000, 0)),
                                 snapshot=GLOBALS + [[a + 0x80, 8], [IMPURE, 4]] + list(snapshot)))

    def base(bitmap=1 << 3, total=0x400, switched=0x300, runtime=0x40, base_time=0):
        st = State(current=a, priority_bitmap=bitmap)
        st.tcb(a, 3, s[0], errno=0x11, runtime=runtime, name=b'outgoing')
        st.w64(TOTAL, total)
        st.w64(SWITCHED, switched)
        st.w64(RUN_BASE, base_time)
        return st

    st = base()
    st.w32(SUSPENDED, 2)
    switch_case('scheduler_suspended_sets_yield_pending', st, supplied={})
    st = base(bitmap=(1 << 3) | (1 << 5))
    st.ready(3, [a])
    st.tcb(b, 5, s[1], errno=0x22, name=b'incoming')
    st.ready(5, [b])
    switch_case('highest_priority_runtime_errno_impure', st, supplied=mtime((0x1500, 0)),
                snapshot=[[b + 0x4b8, 4], [READY + 5 * 0x14, 0x14]])
    st = base()
    st.tcb(b, 3, s[1], errno=0x22, name=b'peer')
    st.ready(3, [a, b], index=0)
    switch_case('round_robin_advances', st, snapshot=[[READY + 3 * 0x14, 0x14]])
    st = base()
    st.tcb(b, 3, s[1], errno=0x22, name=b'peer')
    st.ready(3, [a, b], index=1)
    switch_case('round_robin_wraps_end_marker', st, snapshot=[[READY + 3 * 0x14, 0x14]])
    st = base()
    st.ready(3, [a])
    switch_case('runtime_equal_no_accumulate', st, supplied=mtime((0x300, 0)))
    st = base(switched=0x1_00000000, base_time=0)
    st.ready(3, [a])
    switch_case('runtime_lower_high_word_no_accumulate', st, supplied=mtime((0xffffffff, 0)))
    st = base(switched=0xfffffff0, runtime=0x00000002_fffffff8)
    st.ready(3, [a])
    switch_case('runtime_carry_and_base_borrow', st, supplied=mtime((0x00000010, 0x2)),
                snapshot=[[RUN_BASE, 8]])
    st.w64(RUN_BASE, 0x1_00000020)
    switch_case('runtime_base_borrow', st, supplied=mtime((0x00000010, 0x2)), snapshot=[[RUN_BASE, 8]])
    for i in range(4):
        st = base()
        st.ready(3, [a])
        st.w32(s[0] + 4 * i, 0xa5a5a5a4)
        switch_case('stack_overflow_word%d' % i, st)
    st = base()
    st.ready(3, [a])
    switch_case('runtime_read_retries_high_word', st,
                supplied=merge(mtime((0x2000, 1), retry=0)))
    for bitmap, prio in ((0x1, 0), (0x100, 8), (0x3ff, 9)):
        st = base(bitmap=bitmap)
        st.tcb(b, prio, s[1], errno=0x22, name=b'selected')
        st.ready(prio, [b])
        switch_case('clz_bitmap_%x' % bitmap, st)
    st = base(bitmap=1 << 7)
    st.ready(3, [a])
    switch_case('empty_selected_list_asserts', st)
    st = base(bitmap=0)
    st.ready(3, [a])
    switch_case('zero_bitmap_reads_list_below_ready_array', st)
    return cases


def port_cases():
    cases = []
    snap = [[trap.PLIC_ENABLE, 12], [trap.EXTERNAL_TABLE + 16 * 0xe, 16], [trap.PLIC_PRIORITY + 4 * 0xe, 4],
            [NEXT_COMPARE, 8], [MTIMECMP, 8]]

    def timer_state():
        st = State()
        st.put(trap.PLIC_ENABLE, bytes.fromhex(words(0x01000000, 0, 0)))
        st.put(trap.EXTERNAL_TABLE, bytes.fromhex(trap.external_table({})))
        st.put(trap.PLIC_PRIORITY, bytes(0x150))
        st.put(MTIMECMP, bytes.fromhex(words(0x77777777, 0x77777777)))
        return st

    for name, supplied in (('stable', mtime((0x12345678, 7))),
                           ('high_word_changed', mtime((0x12345678, 8), retry=7)),
                           ('next_compare_carry', mtime((0xfffffc00, 7))),
                           ('both_compares_carry', mtime((0xfffffe00, 0xffffffff)))):
        cases.append(kernel_case('setup_timer_' + name, 'port', [op('setup_timer')], timer_state(),
                                 supplied=supplied, snapshot=snap))
    st = State()
    st.w32(ACK_REGISTER, 0x99999999)
    cases.append(kernel_case('source14_original_object', 'port', [op('source14')], st,
                             snapshot=[[ACK_REGISTER, 4]]))
    st.w32(SOURCE14_OBJECT, 0x91005020)
    cases.append(kernel_case('source14_other_object', 'port', [op('source14')], st, snapshot=[[ACK_REGISTER, 4]]))
    st = State()
    cases.append(kernel_case('runtime_init_then_read', 'port', [op('runtime_init'), op('runtime_read')], st,
                             supplied=merge(mtime((0xfffff000, 4)), mtime((0x00000100, 5), retry=4)),
                             snapshot=[[RUN_BASE, 8]]))
    stack, base_ = STACKS[0], STACKS[0]
    st = State()
    st.put(stack, bytes([0x5c]) * 0x400)
    top = stack + 0x3f8
    cases.append(kernel_case('init_stack_frame', 'port', [op('init_stack', top, base_, 0x70aa1234, 0x13572468)],
                             st, snapshot=[[top - FRAME, FRAME]]))
    cases.append(kernel_case('task_exit_deletes_self', 'port', [op('task_exit')], State()))
    return cases


def create_cases():
    a, b = TCBS[4], TCBS[5]
    cases = []
    name_long = NAMES
    name_short = NAMES + 0x40

    def state(current=0, running=0, tasks=0, cur_prio=0):
        st = State(current=current, running=running)
        st.w32(NUM_TASKS, tasks)
        st.w32(TASK_NUMBER, 7)
        st.put(name_long, b'a-very-long-task-name-over-twenty\0')
        st.put(name_short, b'idle\0')
        st.put(STACKS[1], bytes([0x3c]) * 0x400)
        st.put(b, bytes(0x90))
        if current:
            st.tcb(current, cur_prio, STACKS[2], name=b'existing')
            st.ready(cur_prio, [current])
            st.w32(current + 0x50, 0)
        return st

    snap = GLOBALS + [[b, 0x148], [b + 0x4b0, 6], [STACKS[1], 0x10], [STACKS[1] + 0x3f8 - FRAME, FRAME]]
    args = lambda prio, name=name_short, stack=STACKS[1], tcb=b, depth=0x100: \
        op('create_static', 0x70bb0001, name, depth, 0x2468ace0, prio, stack, tcb)
    cases.append(kernel_case('create_first_task_initializes_lists', 'create', [args(2)], state(), snapshot=snap))
    cases.append(kernel_case('create_long_name_clamped_priority', 'create', [args(15, name=name_long)], state(),
                             snapshot=snap))
    cases.append(kernel_case('create_null_name', 'create', [args(1, name=0)], state(), snapshot=snap))
    for label, prio in (('higher', 6), ('equal', 4), ('lower', 2)):
        cases.append(kernel_case('create_before_start_' + label, 'create', [args(prio)],
                                 state(current=a, tasks=1, cur_prio=4), snapshot=snap + [[a + 0x50, 4]]))
    for label, prio in (('higher_yields', 6), ('lower_no_yield', 2)):
        cases.append(kernel_case('create_running_' + label, 'create', [args(prio)],
                                 state(current=a, tasks=1, cur_prio=4, running=1), snapshot=snap + [[a + 0x50, 4]]))
    cases.append(kernel_case('create_null_stack_asserts', 'create', [args(2, stack=0)], state()))
    cases.append(kernel_case('create_null_tcb_asserts', 'create', [args(2, tcb=0)], state()))
    stops = {str(trap.START_MRET): 'mret'}
    cases.append(kernel_case('create_then_start_first_task', 'create',
                             [args(3), op('start', registers=True)], state(), snapshot=[[b, 4]], stops=stops))
    return cases


def connected_cases():
    cases = []
    a, b = trap.TCB_A, trap.TCB_B

    def kernel_state(st, tick=100, nxt=200, prio_a=3, prio_b=3, ready_b=True, delayed_b=None, bitmap=None):
        st.w32(TICK_COUNT, tick)
        st.w32(NEXT_UNBLOCK, nxt)
        st.w32(RUNNING, 1)
        for tcb, prio, stack in ((a, prio_a, trap.TASK_A_STACK - 0x200), (b, prio_b, 0x81200000)):
            st.put(tcb + 4, bytes(0x28))
            st.w32(tcb + 0x2c, prio)
            st.w32(tcb + 0x30, stack)
            st.put(tcb + 0x80, bytes(8))
            st.w32(tcb + 0x4b8, 0x40 + prio)
            st.put(stack, struct.pack('<4I', *[STACK_FILL] * 4))
        st.w64(TOTAL, 0x10)
        st.w64(SWITCHED, 0x8)
        if ready_b and prio_a == prio_b:
            st.ready(prio_a, [a, b], index=0)
        else:
            st.ready(prio_a, [a])
            if ready_b:
                st.ready(prio_b, [b])
        if delayed_b is not None:
            st.delayed([(b, delayed_b)])
        st.w32(TOP_READY, bitmap if bitmap is not None else (1 << prio_a) | ((1 << prio_b) if ready_b else 0))
        return st

    def from_trap(name, cause, kernel, supplied, **kw):
        base = trap.trap_case(name, cause, **kw)
        for key in (str(TICK), str(SWITCH)):
            base['stubs'].pop(key, None)
        st = kernel(State(current=a))
        memory = st.memory() + base['memory']
        case = kernel_case(name, 'connected', base['operations'], State(), supplied=supplied,
                           csrs=[base['csrs'][str(n)] for n in CSRS], registers=base['registers'],
                           extra_stubs={int(k): v for k, v in base['stubs'].items()},
                           stops=base['stops'])
        for o in case['operations']:
            o['result'] = o['result_high'] = False
        case['fregisters'] = base['fregisters']
        case['memory'] = memory
        case['snapshot'] = base['snapshot'] + GLOBALS + [[a + 0x80, 8], [IMPURE, 4]]
        return case

    def timer_only(name, kernel, supplied):
        st = kernel(State(current=a))
        st.w64(NEXT_COMPARE, 0x7_00001000)
        st.put(MTIMECMP, bytes(8))
        st.put(trap.TASK_A_STACK - 0x200, bytes([0xa5]) * 0x200)
        return kernel_case(name, 'connected', [op('timer')], st, supplied=supplied,
                           snapshot=GLOBALS + [[NEXT_COMPARE, 8], [MTIMECMP, 8]])

    cases.append(timer_only('timer_handler_tick_without_switch',
                            lambda st: kernel_state(st, ready_b=False), {}))
    cases.append(timer_only('timer_handler_time_slice_switch', kernel_state, mtime((0x20, 0))))
    cases.append(from_trap('trap_timer_round_robin_resumes_peer', 0x80000007, kernel_state, mtime((0x30, 0))))
    cases.append(from_trap('trap_timer_wakes_higher_priority', 0x80000007,
                           lambda st: kernel_state(st, nxt=101, prio_b=6, ready_b=False, delayed_b=101),
                           mtime((0x40, 0))))
    cases.append(from_trap('trap_timer_no_switch_keeps_task', 0x80000007,
                           lambda st: kernel_state(st, ready_b=False), {}))
    cases.append(from_trap('trap_yield_selects_peer', 11, kernel_state, mtime((0x50, 0)),
                           a7=trap.SYSCALL_YIELD, epc_half=0x0073))
    table = {0xe: (SOURCE14, 0, 1, 1)}
    cases.append(from_trap('trap_source14_acknowledges', 0x8000000b,
                           lambda st: kernel_state(st, ready_b=False), {trap.PLIC_CLAIM: [0xe]}, table=table,
                           extra_memory=[[ACK_REGISTER, words(0)]]))
    cases[-1]['snapshot'].append([ACK_REGISTER, 4])
    # Scheduler start with the actual timer setup, registration and enable.
    st = State(current=b)
    st.put(trap.PLIC_ENABLE, bytes(12))
    st.put(trap.EXTERNAL_TABLE, bytes.fromhex(trap.external_table({})))
    st.put(trap.PLIC_PRIORITY, bytes(0x150))
    st.put(MTIMECMP, bytes(8))
    st.put(b, bytes.fromhex(words(trap.TASK_B_FRAME)))
    st.put(trap.TASK_B_FRAME, bytes.fromhex(trap.frame_bytes(trap.TASK_B_FRAME, 0x6b000000)))
    cases.append(kernel_case('scheduler_start_actual_timer_setup', 'connected', [op('scheduler', registers=True)], st,
                             supplied=mtime((0x0badf00d, 3)),
                             csrs=(0x20, 0x1808, 0x8, trap.TRAP_ENTRY, 0x51515151, trap.CODE_AREA, 0x8000000b,
                                   0x21, 0x81100000),
                             stops={str(trap.START_MRET): 'mret'},
                             snapshot=[[trap.PLIC_ENABLE, 12], [trap.EXTERNAL_TABLE + 16 * 0xe, 16],
                                       [NEXT_COMPARE, 8], [MTIMECMP, 8]]))
    return cases


def native_vectors():
    cases = []
    for case in port_cases() + create_cases() + tick_cases() + switch_cases() + connected_cases():
        case['expected'] = contract(case)
        cases.append(case)
    guards = trap.CODE + trap.DATA + CODE + DATA
    return dict(schema=1, bound_per_case=BOUND, guards=[dict(address=a, size=n, sha256=h) for a, n, h in guards],
                cases=cases)


# Static evidence.
def direct_target(memory, site):
    """Target of a jal/j or c.j/c.jal at site (raw decoder independent of the disassembler)."""
    half = struct.unpack('<H', memory.read(site, 2))[0]
    if half & 3 == 3:
        w = struct.unpack('<I', memory.read(site, 4))[0]
        if w & 0x7f != 0x6f:
            raise ValueError(f'not a jal at {site:#x}')
        imm = ((w >> 31) & 1) << 20 | ((w >> 12) & 0xff) << 12 | ((w >> 20) & 1) << 11 | ((w >> 21) & 0x3ff) << 1
        return word(site + trap.sx(imm, 21))
    if half & 0x6003 != 0x2001:
        raise ValueError(f'not a compressed jump at {site:#x}')
    bit = lambda i: (half >> i) & 1
    imm = (bit(12) << 11 | bit(8) << 10 | ((half >> 9) & 3) << 8 | bit(6) << 7 | bit(7) << 6 | bit(2) << 5 |
           bit(11) << 4 | ((half >> 3) & 7) << 1)
    return word(site + trap.sx(imm, 12))


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in trap.CODE + trap.DATA + CODE + DATA:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    copy = trap.COPY
    for address, size, _ in CODE:
        if address >= copy['destination']:
            source = copy['source'] + address - copy['destination']
            if memory.data[source - 0x70160000:source - 0x70160000 + size] != memory.read(address, size):
                raise ValueError('copied code differs from its load image')
    table = memory.read(CLZ_TABLE, 0x100)
    if any(table[i] != i.bit_length() for i in range(0x100)):
        raise ValueError('clz table is not a bit-length table')
    if struct.unpack('<I', memory.read(SOURCE14_OBJECT, 4))[0] != SOURCE14_ORIGINAL:
        raise ValueError('source-14 object')
    for site, target in CALL_SITES:
        if direct_target(memory, site) != target:
            raise ValueError(f'call site {site:#x}')
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
        reused_trap_ranges=len(trap.CODE + trap.DATA),
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        kernel_layout=dict(
            max_priorities=PRIORITIES, tcb_size=f'{TCB_SIZE:#x}', ready_lists=f'{READY:#010x}',
            delayed_lists=[f'{DELAYED1:#010x}', f'{DELAYED2:#010x}'], pending_ready=f'{PENDING_READY:#010x}',
            termination=f'{TERMINATION:#010x}', suspended=f'{SUSPENDED_LIST:#010x}',
            tick_count=f'{TICK_COUNT:#010x}', next_unblock=f'{NEXT_UNBLOCK:#010x}',
            top_ready_bitmap=f'{TOP_READY:#010x}', impure_ptr=f'{IMPURE:#010x}',
            reent_size='0x428', name_bytes=20, initial_mstatus='0x7880', initial_hsp_control='0x21',
            stack_bound='pxStack + 0x198', tick_compare_step=1000),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Original FreeRTOS list, tick, context-selection, port timer, run-time counter, stack/task '
            'initialization, ready-list insertion, critical-section and static-creation bodies execute in an '
            'emulator over authored kernel state, TCBs, stacks and supplied mtime/claim values; no hardware '
            'timer or interrupt is delivered and mret is not executed.',
            'memset, configASSERT, the critical-section diagnostic body, vTaskDelete, the stack-overflow hook '
            'and the ecall yield wrapper are supplied. Assert, task_delete and yield stops are harness stops.',
            'Andes CSR 0x7c6/0x7c7 are interpreted as hardware stack-protection control and bound from the '
            'documented AndeStar V5 CSR numbering; the timer frequency, hook behavior, dynamic allocation, '
            'deletion, blocking APIs and live multi-task scheduling remain unproved.'])


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
        parser.exit(2, f'Cannot inspect main FreeRTOS kernel paths: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
