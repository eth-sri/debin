import os
import ctypes
from common import constants

get_char = constants.PRINTABLE.__getitem__


def write_progress(msg, binary):
    if binary.config.PROGRESS_PATH != '':
        with open(binary.config.PROGRESS_PATH, 'w') as w:
            w.write(msg)


def adapt_int_width(n, width, signed=True):
    n = int(n)

    if width == 1:
        result = n
    elif width == 2:
        result = n
    elif width == 4:
        result = ctypes.c_int8(n).value if signed else ctypes.c_uint8(n).value
    elif width == 8:
        result = ctypes.c_int8(n).value if signed else ctypes.c_uint8(n).value
    elif width == 16:
        result = ctypes.c_int16(n).value if signed else ctypes.c_uint16(n).value
    elif width == 32:
        result = ctypes.c_int32(n).value if signed else ctypes.c_uint32(n).value
    elif width == 64:
        result = ctypes.c_int64(n).value if signed else ctypes.c_uint64(n).value
    else:
        result = n
    return result


def encode_address(n, binary):
    return encode_kbytes(n, int(binary.config.ADDRESS_BYTE_SIZE))


def decode_address(bs, binary):
    return decode_kbytes(bs, int(binary.config.ADDRESS_BYTE_SIZE))


def encode_kbytes(n, k):
    bs = bytearray()
    bs.append(n & 0xff)
    for i in range(0, k - 1):
        n = n >> 8
        bs.append(n & 0xff)
    return bs


def decode_kbytes(bs, k):
    n = 0
    for i in range(0, k):
        n += bs[i] << (i * 8)
    return n


def set_global_machine_arch(arch, binary):
    binary.config.MACHINE_ARCH = arch
    if arch == 'x86':
        binary.config.REG_MAPPING = constants.REG_MAPPING_x86
        binary.config.SYSCALL_TABLE = constants.SYSCALL_TABLE_x86
        binary.config.ADDRESS_BYTE_SIZE = 4
        binary.config.HIGH_PC = 0x7fffffff
    elif arch == 'x64':
        binary.config.REG_MAPPING = constants.REG_MAPPING_x64
        binary.config.SYSCALL_TABLE = constants.SYSCALL_TABLE_x64
        binary.config.ADDRESS_BYTE_SIZE = 8
        binary.config.HIGH_PC = 0x7fffffffffffffff
    elif arch == 'ARM':
        binary.config.REG_MAPPING = constants.REG_MAPPING_arm
        binary.config.SYSCALL_TABLE = constants.SYSCALL_TABLE_arm
        binary.config.ADDRESS_BYTE_SIZE = 4
        binary.config.HIGH_PC = 0x7fffffff


def encode_uleb128(num):
    bs = bytearray()

    b = num & 0x7f
    num = num >> 7
    if num != 0:
        b = b | 0x80
    bs.append(b)
    while num != 0:
        b = num & 0x7f
        num = num >> 7
        if num != 0:
            b = b | 0x80
        bs.append(b)
    return bs


def encode_sleb128(num):
    bs = bytearray()

    b = num & 0x7f
    num = num >> 7
    more = not (((num == 0) and ((b & 0x40) == 0)) or ((num == -1) and ((b & 0x40) != 0)))
    if more:
        b = b | 0x80
    bs.append(b)
    while more:
        b = num & 0x7f
        num = num >> 7
        more = not (((num == 0) and ((b & 0x40) == 0)) or ((num == -1) and ((b & 0x40) != 0)))
        if more:
            b = b | 0x80
        bs.append(b)
    return bs


def myord(n):
    if isinstance(n, int):
        return n
    elif isinstance(n, str):
        return ord(n)


def decode_uleb128(bs):
    num = 0
    shift = 0
    for b in bs:
        num = num | ((myord(b) & 0x7f) << shift)
        shift = shift + 7
    return num


def decode_sleb128(bs):
    if (len(bs) == 0):
        return 0
    num = 0
    shift = 0

    b = myord(bs[0])
    num = num | ((b & 0x7f) << shift)
    shift = shift + 7
    for i in range(1, len(bs)):
        b = myord(bs[i])
        num = num | ((b & 0x7f) << shift)
        shift = shift + 7

    if b & 0x40:
        num = num | ((-1) << shift)
    return num
