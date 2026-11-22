#!/usr/bin/env python3
"""Bootloader recovery-entry gate: the boot-reason/power/two-key detector.

This scope executes the original detector ``0x80c00312`` end to end in the
``boot-runtime`` project.  The boot manager ``0x80c00454`` calls it to decide
whether to enter recovery before it finally, unconditionally, calls the main
firmware boot ``0x80c00918`` (executed in
[MAIN_BOOT_GATE.md](MAIN_BOOT_GATE.md)).  A failed main-firmware verification
therefore does **not** fall through to recovery on its own: recovery is entered
only when this detector returns 1 or when a pre-written ``upgrade`` environment
record requests it.  The detector requires the boot reason to be neither 3 nor
6, external power present, and two keys held together through its windows.

The boot-reason reader, the power check, the key poll and the millisecond delay
are supplied stubs; the key poll writes a per-index sequence of button states to
its output pointer and the power check writes its flag, both into the quiet
stack window, so no vendor peripheral is driven.  ``mret`` is not executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import main_trap_irq as trap
    from .recovery_validator import image_memory, BOOT_HASH
else:
    import main_freertos_kernel as kernel
    import main_trap_irq as trap
    from recovery_validator import image_memory, BOOT_HASH

MASK = 0xffffffff
BOUND = 5000

DETECTOR = 0x80c00312          # recovery-entry detector
REASON = 0x80c0ec70           # boot reason reader
POWER = 0x80c216ac            # power-supply check (writes a flag)
POLL = 0x80c2d0ba             # key poll (writes a button state byte)
DELAY = 0x80c16884            # millisecond delay
LOG = 0x80c1cd7a              # tagged logger
BOOT_MANAGER = 0x80c00454     # caller; chooses recovery vs the final main boot
BOOT_FIRMWARE = 0x80c00918    # unconditional final call of the boot manager
RECOVERY_LAUNCH = 0x80c0098c  # recovery boot, gated by this detector / upgrade record

CONFIRM_WINDOW = 20            # 0x14 iterations, each a 0x32 ms poll
POLL_DELAY_MS = 0x32
SKIP_REASONS = (3, 6)
STRINGS = {
    'tag': (0x80c32a78, b'BOOT_MAIN'),
    'reason': (0x80c32aa8, b'boot check reason %d'),
    'no_power': (0x80c32ac0, b'boot no power supply !'),
    'press': (0x80c32af0, b'boot press detected !'),
    'enter': (0x80c32ad8, b'backup check key pass !'),
}

CODE = ((DETECTOR, 0x142, '8d6ee40e377b740e84ec51853a7945a5565c4ae1168634301eef6a48ebb6bb6f'),)
CALL_SITES = (
    (0x80c0031c, REASON), (0x80c0034a, POWER), (0x80c00384, POLL), (0x80c00394, DELAY),
    (0x80c005e4, BOOT_FIRMWARE), (0x80c0068e, RECOVERY_LAUNCH), (0x80c006ac, RECOVERY_LAUNCH),
)
CSRS = kernel.CSRS
HARNESS_STACK = kernel.HARNESS_STACK
QUIET = ((0x81000000, 0x81002000),)
POWER_FLAG_ADDR = HARNESS_STACK - 0x40 + 0x10
KEY0_ADDR = HARNESS_STACK - 0x40 + 0xe
KEY1_ADDR = HARNESS_STACK - 0x40 + 0xf


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.reason = case['reason']
        self.power_status = case['power_status']
        self.power_flag = case['power_flag']
        self.keys = {0: list(case['keys']['0']), 1: list(case['keys']['1'])}
        self.recovery = 0

    def leaf(self, address):
        self.actions.append('call:%d' % address)
        return self.stubs[address].get('value', 0) if address in self.stubs else 0

    def poll(self, index):
        self.actions.append('call:%d' % POLL)
        return self.keys[index].pop(0)

    def power(self):
        self.actions.append('call:%d' % POWER)
        return self.power_status, self.power_flag

    def detect(self):
        self.leaf(REASON)
        self.leaf(LOG)
        if self.reason in SKIP_REASONS:
            return
        status, flag = self.power()
        if status != 0 or flag == 0:
            self.leaf(LOG)
            return
        while True:                                  # wait for release
            if self.poll(0) == 0:
                break
            self.leaf(DELAY)
        remaining = CONFIRM_WINDOW                    # wait for both keys down
        while True:
            k0, k1 = self.poll(0), self.poll(1)
            if k0 == 1 and k1 == 1:
                break
            remaining -= 1
            self.leaf(DELAY)
            if remaining == 0:
                return
        remaining = CONFIRM_WINDOW                    # confirm the hold
        self.leaf(LOG)
        while True:
            k0, k1 = self.poll(0), self.poll(1)
            if k0 == 0:
                return
            if k1 == 0:
                return
            remaining -= 1
            self.leaf(DELAY)
            if remaining == 0:
                self.leaf(LOG)
                self.recovery = 1
                return

    def operation(self, op):
        if op['name'] != 'detect':
            raise ValueError('operation')
        self.detect()
        return self.recovery       # the detector returns 1 to enter recovery, else 0


def contract(case):
    if case['scope'] != 'detect' or len(case['operations']) != 1:
        raise ValueError('recovery gate scope')
    return Model(case).run()


def stubs(reason, power_status, power_flag, keys):
    return {
        str(REASON): dict(kind='return', value=reason & MASK, args=0),
        str(LOG): dict(kind='return', args=0),
        str(DELAY): dict(kind='return', args=0),
        str(POWER): dict(kind='store', out_arg=0, size=4, value=power_flag, value_ret=power_status, args=0),
        str(POLL): dict(kind='store', out_arg=3, index_arg=2, size=1,
                        seqs={'0': list(keys[0]), '1': list(keys[1])}, value_ret=0, args=0),
    }


def case(name, reason, power_status=0, power_flag=1, keys=None):
    keys = keys or {0: [0], 1: [0]}
    op = dict(name='detect', entry=DETECTOR, call=True, args=[0x81340000], registers=False,
              result=True, result_high=False)
    return dict(
        name='main_recovery_gate_' + name, scope='detect', reason=reason, power_status=power_status,
        power_flag=power_flag, keys={'0': list(keys[0]), '1': list(keys[1])}, supplied={},
        quiet=[list(q) for q in QUIET], csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': HARNESS_STACK}, fregisters={},
        stubs=stubs(reason, power_status, power_flag, keys), stops={}, snapshot=[], operations=[op],
        memory=[])


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('reason_ota_skips', reason=6))
    add(case('reason_reset_skips', reason=3))
    add(case('no_external_power', reason=0, power_flag=0))
    add(case('power_check_error', reason=0, power_status=1))
    add(case('keys_never_pressed_times_out', reason=0,
             keys={0: [0] + [0] * 40, 1: [0] * 40}))
    add(case('recovery_gesture_succeeds', reason=0,
             keys={0: [0] + [1] * 44, 1: [1] * 44}))
    add(case('key_released_during_confirm_aborts', reason=0,
             keys={0: [0, 1, 1, 1, 1], 1: [1, 1, 1, 0]}))
    add(case('second_key_late_then_held', reason=0,
             keys={0: [0] + [1] * 44, 1: [0, 0, 1] + [1] * 43}))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in CODE:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for key, (addr, text) in STRINGS.items():
        if memory.read(addr, len(text)) != text:
            raise ValueError(f'string {key} differs at {addr:#x}')
    for site, target in CALL_SITES:
        if kernel.direct_target(memory, site) != target:
            raise ValueError(f'call site {site:#x}')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
    return dict(
        boot_sha256=BOOT_HASH, vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        detector=f'{DETECTOR:#010x}', boot_manager=f'{BOOT_MANAGER:#010x}',
        boot_firmware=f'{BOOT_FIRMWARE:#010x}', recovery_launch=f'{RECOVERY_LAUNCH:#010x}',
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        skip_reasons=list(SKIP_REASONS), confirm_window=CONFIRM_WINDOW, poll_delay_ms=POLL_DELAY_MS,
        requires='boot reason not in {3,6}, external power present, two keys held through both windows',
        strings={k: dict(address=f'{a:#010x}', text=t.decode('latin1')) for k, (a, t) in STRINGS.items()},
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The recovery-entry detector executes in an emulator over authored state with the boot-reason '
            'reader, power check, key poll and delay supplied; the key poll writes a scripted per-index '
            'button sequence and the power check writes its flag into the quiet stack window. No real key '
            'matrix, power rail or timer is read.',
            'The boot manager 0x80c00454 and the final main boot 0x80c00918 are not re-executed here; their '
            'control flow is read statically. The upgrade-record software recovery request and the recovery '
            'image validation are covered elsewhere.',
            'The two-key-plus-power and upgrade-record branches describe the analyzed boot manager. '
            'Physical key mapping, debounce timing, the power threshold, service interfaces and stock '
            'restoration still require on-device evidence.'])


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
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, IndexError) as error:
        parser.exit(2, f'Cannot inspect recovery gate: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
