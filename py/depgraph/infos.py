from elements.givs import IntConst, StringConst, SwitchTable, Flag, Insn
from elements.givs import CodeOffset, VirtualElm
from elements.offsets import GivOffset, TempOffset, IndirectOffset
from elements.offsets import DirectOffset, StringArrayOffset
from elements.function import Function
from elements.regs import GivReg, Reg
from elements.ttype import Ttype


def coarse(node):
    if isinstance(node, IntConst):
        return 'INT'
    elif isinstance(node, StringConst):
        return 'STR'
    elif isinstance(node, SwitchTable):
        return 'SWITCH'
    elif isinstance(node, Flag):
        return '{}'.format(node.base_flag)
    elif isinstance(node, Insn):
        return node.name
    elif isinstance(node, CodeOffset):
        return 'CODE'
    elif isinstance(node, VirtualElm):
        return 'VIRTUAL'
    elif isinstance(node, IndirectOffset):
        return '{}:O'.format(node.base_pointer)
    elif isinstance(node, TempOffset):
        return '{}:T'.format(node.base_pointer)
    elif isinstance(node, GivOffset):
        return node.offset
    elif isinstance(node, DirectOffset):
        return 'DIRECT'
    elif isinstance(node, StringArrayOffset):
        return 'SARRAY'
    elif isinstance(node, GivReg):
        return '{}:GIVR'.format(node.base_register)
    elif isinstance(node, Reg):
        return '{}:R'.format(node.base_register)
    elif isinstance(node, Function):
        return 'FUNC'
    elif isinstance(node, Ttype):
        return '{}:TTYPE'.format(coarse(node.owner))


def fine(node):
    if isinstance(node, IntConst):
        return 'INT({})({})'.format(node.width, node.value)
    elif isinstance(node, StringConst):
        return 'STR'
    elif isinstance(node, SwitchTable):
        return 'SWITCH'
    elif isinstance(node, Flag):
        return '{}:{}'.format(node.base_flag, node.index)
    elif isinstance(node, Insn):
        return node.name
    elif isinstance(node, CodeOffset):
        return 'CODE'
    elif isinstance(node, VirtualElm):
        return 'VIRTUAL'
    elif isinstance(node, IndirectOffset):
        return '{}:O:{}'.format(node.base_pointer, node.offset)
    elif isinstance(node, TempOffset):
        return '{}:T:{}'.format(node.base_pointer, node.offset)
    elif isinstance(node, GivOffset):
        return node.offset
    elif isinstance(node, DirectOffset):
        return 'DIRECT'
    elif isinstance(node, StringArrayOffset):
        return 'SARRAY'
    elif isinstance(node, GivReg):
        return '{}:GIVR:{}'.format(node.base_register, node.index)
    elif isinstance(node, Reg):
        return '{}:R:{}'.format(node.base_register, node.index)
    elif isinstance(node, Function):
        return 'FUNC'
    elif isinstance(node, Ttype):
        return '{}:TTYPE'.format(fine(node.owner))


INFOS = [coarse]
