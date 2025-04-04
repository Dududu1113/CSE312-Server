import hashlib
import base64
import struct


def compute_accept(key):
    guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    combined = key + guid
    sha1 = hashlib.sha1(combined.encode()).digest()
    return base64.b64encode(sha1).decode()


class WSFrame:
    def __init__(self, fin_bit, opcode, payload_length, payload):
        self.fin_bit = fin_bit
        self.opcode = opcode
        self.payload_length = payload_length
        self.payload = payload


def parse_ws_frame(data):
    first_byte = data[0]
    fin_bit = (first_byte >> 7) & 0x1
    opcode = first_byte & 0xF

    second_byte = data[1]
    mask_bit = (second_byte >> 7) & 0x1
    payload_len = second_byte & 0x7F

    offset = 2
    if payload_len == 126:
        payload_len = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2
    elif payload_len == 127:
        payload_len = struct.unpack('>Q', data[offset:offset + 8])[0]
        offset += 8

    mask = None
    if mask_bit:
        mask = data[offset:offset + 4]
        offset += 4

    payload = data[offset:offset + payload_len]
    if mask_bit and mask:
        payload = bytes([payload[i] ^ mask[i % 4] for i in range(len(payload))])

    return WSFrame(fin_bit, opcode, payload_len, payload)


def generate_ws_frame(payload):
    fin_bit = 1
    opcode = 0x1
    payload_len = len(payload)

    first_byte = (fin_bit << 7) | opcode
    header = bytearray([first_byte])

    if payload_len <= 125:
        header.append(payload_len)
    elif payload_len <= 65535:
        header.append(126)
        header.extend(struct.pack('>H', payload_len))
    else:
        header.append(127)
        header.extend(struct.pack('>Q', payload_len))
    return bytes(header) + payload