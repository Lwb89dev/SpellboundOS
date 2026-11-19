#!/usr/bin/env python3
"""Bootloader main-firmware load, signature gate and image handoff decision.

This scope executes the original bootloader boot decision
``FUN_80c00918`` and the firmware loader ``FUN_80c00876`` end to end over
authored state, supplying the file-system leaves (stat/open/read/close), the
signature verifier ``0x80c0e2b6`` and the image handoff ``0x80c0084a`` as
stubs.  It establishes, by execution rather than static reading, that the
bootloader hands control to the main firmware at ``0x70160000`` only when the
loader returns success, which happens only when the signature verifier returns
nonzero; a failed verification, a short read, a failed open or an oversize
image all return without any handoff.

The signature verifier internals (ECDSA secp256k1 over SHA-256 with the
embedded public key) are already executed for the recovery image in
[RECOVERY_VALIDATOR_NATIVE.md](RECOVERY_VALIDATOR_NATIVE.md); here the verifier
result is supplied both ways to exercise the main-firmware boot branch.  No
flash is read or written, no recovery is entered and ``mret``/the indirect jump
into the image are not executed.
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
    from .zrpc_packets import MAIN_HASH
else:
    import main_freertos_kernel as kernel
    import main_trap_irq as trap
    from recovery_validator import image_memory, BOOT_HASH
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
BOUND = 5000

BOOT = 0x80c00918               # boot decision: stat, size gate, load, handoff/log
LOADER = 0x80c00876            # firmware loader: stat/open/read/close/verify
INIT = 0x80c0b190              # pre-load init
STAT = 0x80c26efc             # file stat (writes size)
OPEN = 0x80c26b14             # file open
READ = 0x80c26ca2             # file read
CLOSE = 0x80c26bec            # file close
VERIFY = 0x80c0e2b6           # main-firmware signature verifier (nonzero = pass)
LOG1 = 0x80c1c776             # printf-style logger
LOG2 = 0x80c1cd7a             # tagged logger
HANDOFF = 0x80c0084a          # image handoff (indirect jump into the image)

FIRMWARE_ENTRY = 0x70160000
SIZE_LIMIT = 0xe00000          # inclusive maximum accepted firmware size
PATH = 0x80c32d30              # "/mnt/system/firmware_sign.bin"
STRINGS = {
    'path': (PATH, b'/mnt/system/firmware_sign.bin'),
    'jump': (0x80c32d50, b'jump to address 0x%08X\r\n'),
    'load_failed': (0x80c32d6c, b'load firmware failed!!!\r\n'),
    'verify_failed': (0x80c32d0c, b'firmware secure verify failed!!!\r\n'),
    'too_large': (0x80c32e44, b'firmware is too large , size 0x%08X, limit 0x%08X'),
}

CODE = (
    (LOADER, 0xa2, '9e42541accca923bec1a07064b5e466e419534663cb8f48072652aa647a22984'),
    (BOOT, 0x74, '50fd5502f0f7a498fa46ff2b352e796a92b4a9b74edb1bda1feb622ca8ddd5c8'),
)
# Direct call sites tying the decision to the loader, verifier and handoff.
CALL_SITES = (
    (0x80c0091c, INIT), (0x80c0092a, STAT), (0x80c00962, LOADER), (0x80c0097a, HANDOFF),
    (0x80c00886, STAT), (0x80c0088e, OPEN), (0x80c008f2, CLOSE), (0x80c00902, VERIFY),
)
CSRS = kernel.CSRS
HARNESS_STACK = kernel.HARNESS_STACK
QUIET = ((0x81000000, 0x81002000),)
# Stack addresses where the stat leaf's size output is read (sp fixed, frames known).
BOOT_SP = HARNESS_STACK - 0x30
BOOT_SIZE_ADDR = BOOT_SP + 0x10
NESTED_LOADER_SP = BOOT_SP - 0x40
NESTED_LOADER_SIZE_ADDR = NESTED_LOADER_SP + 0x20
DIRECT_LOADER_SP = HARNESS_STACK - 0x40
DIRECT_LOADER_SIZE_ADDR = DIRECT_LOADER_SP + 0x20


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Model(kernel.Model):
    def call(self, address, *args):
        if address in self.stubs:
            return trap.Model.call(self, address, *args)
        raise ValueError(f'unmodelled callee {address:#x}')

    def stub_value(self, address):
        return self.stubs[address].get('value', 0)

    def firmware_loader(self, size):
        self.call(STAT)
        handle = self.stub_value(OPEN)
        self.call(OPEN)
        if handle & 0x80000000:                 # open failed (signed negative)
            self.call(LOG2)
            return MASK
        read = self.stub_value(READ)
        self.call(READ)
        if read != size:                        # short read
            self.call(LOG2)
            self.call(CLOSE)
            return MASK
        self.call(CLOSE)
        verified = self.stub_value(VERIFY)
        self.call(VERIFY)
        if verified != 0:                       # signature verified
            return 0
        self.call(LOG1)                         # "firmware secure verify failed!!!"
        return MASK

    def boot_firmware(self, size):
        self.call(INIT)
        self.call(STAT)
        if size < SIZE_LIMIT + 1:
            result = self.firmware_loader(size)
            if result == 0:
                self.call(LOG1)                 # "jump to address 0x%08X"
                self.call(HANDOFF, FIRMWARE_ENTRY)   # stop 'handoff'
            else:
                self.call(LOG1)                 # "load firmware failed!!!"
        else:
            self.call(LOG2)                     # "firmware is too large ..."

    def operation(self, op):
        kind = op['name'].split('#')[0]
        if kind == 'boot':
            self.boot_firmware(op['size'])
        elif kind == 'loader':
            self.firmware_loader(op['size'])
        else:
            raise ValueError('operation')
        return None


def contract(case):
    if case['scope'] not in ('boot', 'loader'):
        raise ValueError('boot gate scope')
    if len(case['operations']) != 1:
        raise ValueError('bounded operations')
    return Model(case).run()


def stub(kind, **extra):
    return dict(kind=kind, args=extra.pop('args', 0), **extra)


def stubs(open_handle=0x5, read_value=None, verify=1, size=0x200000):
    read_value = size if read_value is None else read_value
    return {
        str(INIT): stub('return'), str(STAT): stub('return'),
        str(OPEN): stub('return', value=open_handle), str(READ): stub('return', value=read_value),
        str(CLOSE): stub('return'), str(VERIFY): stub('return', value=verify),
        str(LOG1): stub('return'), str(LOG2): stub('return'),
        str(HANDOFF): stub('stop', label='handoff', args=1),
    }


def case(name, scope, size, open_handle=0x5, read_value=None, verify=1):
    entry = BOOT if scope == 'boot' else LOADER
    op = dict(name=scope, entry=entry, call=True, args=[], registers=False, result=False,
              result_high=False, size=size)
    # Pre-seed the stat size output (little-endian) at each address the code reads.
    addresses = (BOOT_SIZE_ADDR, NESTED_LOADER_SIZE_ADDR) if scope == 'boot' else (DIRECT_LOADER_SIZE_ADDR,)
    seeded = [[addr, size.to_bytes(4, 'little').hex()] for addr in addresses]
    return dict(
        name='main_boot_gate_' + name, scope=scope, supplied={}, quiet=[list(q) for q in QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': HARNESS_STACK}, fregisters={},
        stubs=stubs(open_handle=open_handle, read_value=read_value, verify=verify, size=size),
        stops={}, snapshot=[], operations=[op], memory=seeded)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('verified_firmware_hands_off', 'boot', 0x200000, verify=1))
    add(case('verify_failure_no_handoff', 'boot', 0x200000, verify=0))
    add(case('oversize_firmware_rejected', 'boot', SIZE_LIMIT + 1))
    add(case('maximum_size_still_loads', 'boot', SIZE_LIMIT, verify=1))
    add(case('open_failure_no_handoff', 'boot', 0x200000, open_handle=MASK))
    add(case('short_read_no_handoff', 'boot', 0x200000, read_value=0x1fffff))
    add(case('loader_verified_returns_success', 'loader', 0x180000, verify=1))
    add(case('loader_verify_failure_returns_error', 'loader', 0x180000, verify=0))
    add(case('loader_open_failure_returns_error', 'loader', 0x180000, open_handle=MASK))
    add(case('loader_short_read_returns_error', 'loader', 0x180000, read_value=0x17ffff))
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
        boot_sha256=BOOT_HASH, main_sha256=MAIN_HASH, vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        boot_decision=f'{BOOT:#010x}', firmware_loader=f'{LOADER:#010x}',
        signature_verifier=f'{VERIFY:#010x}', image_handoff=f'{HANDOFF:#010x}',
        firmware_entry=f'{FIRMWARE_ENTRY:#010x}', firmware_path=STRINGS['path'][1].decode(),
        size_limit=f'{SIZE_LIMIT:#x}',
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        strings={k: dict(address=f'{a:#010x}', text=t.decode('latin1')) for k, (a, t) in STRINGS.items()},
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The bootloader boot decision and firmware loader execute in an emulator over authored state '
            'with the file-system leaves, the signature verifier 0x80c0e2b6 and the image handoff 0x80c0084a '
            'supplied; the indirect jump into the loaded image is a harness stop and is not taken.',
            'The verifier result is supplied both ways to exercise the branch; its ECDSA/SHA-256 internals '
            'are executed for the recovery image elsewhere and are not re-executed here. No signature bypass '
            'is implied by supplying a passing result: a valid signature still requires the private key.',
            'This proves the control-flow gate (the main firmware is entered only on loader success, which '
            'needs a nonzero verifier result), not device enforcement, the recovery fall-back policy, a '
            'physical flash backup or any viable standalone-boot route.'])


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
        parser.exit(2, f'Cannot inspect main boot gate: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
