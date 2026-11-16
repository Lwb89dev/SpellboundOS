"""Selected stock TX chunk rules and a stricter bounded host reassembler.

Host only. No ACK/retry timing, allocator ownership or scheduler is emulated.
The stock exact-multiple continuation bit is preserved, not silently repaired.
"""
import struct

if __package__:
    from .zrpc_packets import crc16, decode_channel, encode_data, uint
else:
    from zrpc_packets import crc16, decode_channel, encode_data, uint


def stock_channels(payload, *, mtu, source, destination, request, session, module,
                   flags=2, timeout_raw=1000):
    uint(mtu, 16)
    uint(timeout_raw, 32)
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 65511 or mtu < 36:
        raise ValueError('requires bounded nonempty payload and room for descriptor')
    fields = dict(source=source, destination=destination, request=request,
                  session=session, module=module, flags=flags)
    if len(payload) + 24 <= mtu:
        return [encode_data(payload, **fields)]
    capacity = mtu - 24
    count = (len(payload) + capacity - 1) // capacity
    if count > 0x3fff:
        raise ValueError('sequence would wrap in the bounded host model')
    descriptor = struct.pack('<4HI', len(payload), count, crc16(payload), 0, timeout_raw)
    packets = [encode_data(descriptor, packed=2, **fields)]
    for index, offset in enumerate(range(0, len(payload), capacity), 1):
        chunk = payload[offset:offset + capacity]
        more = len(chunk) == capacity
        packets.append(encode_data(chunk, packed=(index << 2) | (2 if more else 0), **fields))
    return packets


class Reassembler:
    """One bounded transfer, in arrival order; stronger guards than native RX.

    A malformed packet clears partial state. A final full-sized stock chunk
    retains its more bit and therefore leaves the transfer pending. No timeout
    or workaround is invented. Returned values are application payload bytes.
    """
    def __init__(self, maximum=65511):
        if type(maximum) is not int or not 1 <= maximum <= 65511:
            raise ValueError('invalid host allocation limit')
        self.maximum = maximum
        self.state = None

    def feed(self, packet):
        try:
            return self._feed(packet)
        except (ValueError, KeyError):
            self.state = None
            raise

    def _feed(self, packet):
        value = decode_channel(packet)
        if value['type'] != 1:
            raise ValueError('expected data packet, not ACK')
        identity = tuple(value[key] for key in ('source', 'destination', 'request', 'session', 'module_raw', 'flags'))
        if value['complete']:
            if self.state is not None or len(value['payload']) > self.maximum:
                raise ValueError('unexpected complete packet or host limit exceeded')
            return value['payload']
        if self.state is None:
            info = value.get('fragment_descriptor')
            if (info is None or not 1 <= info['total'] <= self.maximum
                    or not 1 <= info['count'] <= 0x3fff or info['crc16'] == 0):
                raise ValueError('missing or invalid fragment descriptor')
            self.state = dict(identity=identity, info=info, chunks=[], size=0)
            return None
        state = self.state
        expected = len(state['chunks']) + 1
        if identity != state['identity'] or value['sequence'] != expected or expected > state['info']['count']:
            raise ValueError('route, session or sequence mismatch')
        if state['size'] + len(value['payload']) > state['info']['total']:
            raise ValueError('fragment length overflow')
        state['chunks'].append(value['payload'])
        state['size'] += len(value['payload'])
        if value['bit1_raw']:
            return None
        payload = b''.join(state['chunks'])
        if expected != state['info']['count'] or len(payload) != state['info']['total'] or crc16(payload) != state['info']['crc16']:
            raise ValueError('final count, length or whole-payload CRC mismatch')
        self.state = None
        return payload
