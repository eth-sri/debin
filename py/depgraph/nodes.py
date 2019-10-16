import json
from common.constants import UNKNOWN_LABEL
from elements.givs import IntConst, StringConst, SwitchTable, Flag, Insn
from elements.givs import CodeOffset, VirtualElm, NodeType, OpNode
from elements.givs import OtherVarNode, SizeNode, UnknownNode
from elements.offsets import GivOffset, TempOffset, StringArrayOffset
from elements.offsets import DirectOffset, IndirectOffset
from elements.regs import GivReg, Reg
from elements.ttype import Ttype
from elements.function import Function
from depgraph.infos import fine, coarse
from collections import OrderedDict


GIV_NODES = (
    IntConst,
    StringConst,
    SwitchTable,
    Flag,
    Insn,
    CodeOffset,
    VirtualElm,
    GivOffset,
    NodeType,
    OpNode,
    OtherVarNode,
    SizeNode,
    UnknownNode,
    TempOffset,
    GivOffset,
    GivReg,
)


INF_NODES = (
    Function,
    DirectOffset,
    StringArrayOffset,
    IndirectOffset,
    Reg,
    Ttype,
)


NODES = (
    IntConst,
    StringConst,
    SwitchTable,
    Flag,
    Insn,
    CodeOffset,
    VirtualElm,
    GivOffset,
    NodeType,
    OpNode,
    OtherVarNode,
    SizeNode,
    UnknownNode,
    TempOffset,
    GivOffset,
    GivReg,
    Function,
    DirectOffset,
    StringArrayOffset,
    IndirectOffset,
    Reg,
    Ttype,
)

FINE_NODES = (
    IndirectOffset,
    IndirectOffset
)


class Nodes:
    def __init__(self, *args, **kwargs):
        self.binary = kwargs['binary']
        self.nodes = dict()
        self.inf_nodes = dict()
        self.giv_nodes = dict()

    def add_node(self, node):
        if node.id not in self.nodes:
            self.nodes[node.id] = node
            if type(node) in GIV_NODES:
                self.giv_nodes[node.id] = node
            elif isinstance(node, Function):
                if node.is_name_given:
                    self.giv_nodes[node.id] = node
                else:
                    self.inf_nodes[node.id] = node
            elif isinstance(node, DirectOffset):
                if node.is_name_given:
                    self.giv_nodes[node.id] = node
                else:
                    self.inf_nodes[node.id] = node
            elif isinstance(node, IndirectOffset):
                if node.n2p_type == self.binary.config.GIV:
                    self.giv_nodes[node.id] = node
                else:
                    self.inf_nodes[node.id] = node
            elif isinstance(node, Reg):
                if node.n2p_type == self.binary.config.GIV:
                    self.giv_nodes[node.id] = node
                else:
                    self.inf_nodes[node.id] = node
            elif isinstance(node, Ttype):
                if type(node.owner) in (Reg, IndirectOffset):
                    if node.owner.n2p_type == self.binary.config.GIV:
                        self.giv_nodes[node.id] = node
                    elif node.owner.n2p_type == self.binary.config.INF:
                        self.inf_nodes[node.id] = node
                if type(node.owner) in (Function, DirectOffset):
                    self.inf_nodes[node.id] = node

    def initialize(self):
        for direct_offset in self.binary.direct_offsets.values():
            self.add_node(direct_offset.ttype)
            if not direct_offset.is_name_given:
                self.add_node(direct_offset)

        for function in self.binary.functions.functions:
            self.add_node(function)
            if function.is_run_init \
                    and (self.binary.config.MODE == self.binary.config.TRAIN and function.init_run):
                self.add_node(function.ttype)
                for indirect_offset in function.indirect_offsets.values():
                    for off in indirect_offset.values():
                        self.add_node(off)
                        self.add_node(off.ttype)
                for reg in function.regs.values():
                    self.add_node(reg)
                    self.add_node(reg.ttype)

    def stat(self):
        for node in self.nodes.values():
            node.stat()

    def to_json(self, clear=False):
        nodes = []
        for node in self.nodes.values():
            if type(node) == IntConst:
                node_name = 'INT[{}][{}]'.format(node.width, node.value)
                node_type = 'giv'
            elif type(node) == StringConst:
                node_name = '\"{}\"'.format(node.value)
                node_type = 'giv'
            elif type(node) == SwitchTable:
                node_name = 'SwitchTable'
                node_type = 'giv'
            elif type(node) == Flag:
                node_name = node.base_flag
                node_type = 'giv'
            elif type(node) == Insn:
                node_name = node.name
                node_type = 'giv'
            elif type(node) == CodeOffset:
                node_name = 'CodeOffset'
                node_type = 'giv'
            elif type(node) == VirtualElm:
                node_name = node.name
                node_type = 'giv'
            elif type(node) == GivOffset:
                node_name = str(node.offset)
                node_type = 'giv'
            elif type(node) == TempOffset:
                node_name = fine(node)
                node_type = 'giv'
            elif type(node) == GivReg:
                node_name = coarse(node)
                node_type = 'giv'
            elif type(node) == NodeType:
                node_name = node.name
                node_type = 'giv'
            elif type(node) == OpNode:
                node_name = node.name
                node_type = 'giv'
            elif type(node) == OtherVarNode:
                node_name = node.name
                node_type = 'giv'
            elif type(node) == SizeNode:
                node_name = 'SIZE[{}]'.format(node.size)
                node_type = 'giv'
            elif type(node) == UnknownNode:
                node_name = 'Unknown'
                node_type = 'giv'
            elif type(node) == Function:
                if node.is_name_given:
                    node_name = node.name
                    node_type = 'giv'
                else:
                    node_name = node.train_name
                    if self.binary.config.UNK_GIV:
                        node_type = 'giv' if node.train_name == UNKNOWN_LABEL else 'inf'
                    else:
                        node_type = 'inf'
            elif type(node) == DirectOffset:
                if node.is_name_given:
                    node_name = node.name
                    node_type = 'giv'
                else:
                    node_name = node.train_name
                    if self.binary.config.UNK_GIV:
                        node_type = 'giv' if node.train_name == UNKNOWN_LABEL else 'inf'
                    else:
                        node_type = 'inf'
            elif type(node) == StringArrayOffset:
                if node.is_name_given:
                    node_name = node.name
                    node_type = 'giv'
                else:
                    node_name = node.train_name
                    if self.binary.config.UNK_GIV:
                        node_type = 'giv' if node.train_name == UNKNOWN_LABEL else 'inf'
                    else:
                        node_type = 'inf'
            elif type(node) == IndirectOffset:
                node_name = node.train_name
                if node.n2p_type == self.binary.config.GIV:
                    node_type = 'giv'
                else:
                    if self.binary.config.UNK_GIV:
                        node_type = 'giv' if node.train_name == UNKNOWN_LABEL else 'inf'
                    else:
                        node_type = 'inf'
            elif type(node) == Reg:
                node_name = node.train_name
                if node.n2p_type == self.binary.config.GIV:
                    node_type = 'giv'
                else:
                    if self.binary.config.UNK_GIV:
                        node_type = 'giv' if node.train_name == UNKNOWN_LABEL else 'inf'
                    else:
                        node_type = 'inf'
            elif type(node) == Ttype:
                node_name = node.train_name
                if type(node.owner) == Reg:
                    if node.owner.n2p_type == self.binary.config.GIV:
                        node_type = 'giv'
                    else:
                        if self.binary.config.UNK_GIV:
                            node_type = 'giv' if node.train_name == UNKNOWN_LABEL else 'inf'
                        else:
                            node_type = 'inf'
                elif type(node.owner) == IndirectOffset:
                    if node.owner.n2p_type == self.binary.config.GIV:
                        node_type = 'giv'
                    else:
                        if self.binary.config.UNK_GIV:
                            node_type = 'giv' if node.train_name == UNKNOWN_LABEL else 'inf'
                        else:
                            node_type = 'inf'
                else:
                    if self.binary.config.UNK_GIV:
                        node_type = 'giv' if node.train_name == UNKNOWN_LABEL else 'inf'
                    else:
                        node_type = 'inf'
            else:
                print(node)

            if clear and node_type == 'inf':
                nodes.append(OrderedDict([('v', node.id), (node_type, '')]))
            else:
                if node_name == UNKNOWN_LABEL:
                    node_name = ''
                nodes.append(OrderedDict([('v', node.id), (node_type, node_name)]))

        return nodes
