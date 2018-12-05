from common import constants
from depgraph.infos import coarse, fine
from depgraph.edgefactory import STMT_EDGE_EXTRACTOR, EXP_EDGE_EXTRACTOR
from depgraph.nodes import FINE_NODES, INF_NODES
from elements.elmfactory import make_node_type, make_size_node
from elements.offsets import StringArrayOffset
from elements.ttype import Ttype
from collections import OrderedDict


class Edges:
    def __init__(self, *args, **kwargs):
        self.binary = kwargs['binary']
        self.edges = set()
        if self.binary.config.STAT_PATH != '':
            self.stat_dict = dict()

    def add_edge(self, a, b, f2, ainfo=None, binfo=None):
        if a is not None \
                and b is not None \
                and (type(a) in INF_NODES or type(b) in INF_NODES):
            self.binary.nodes.add_node(a)
            self.binary.nodes.add_node(b)
            if f2.count('{}') == 0:
                edge = Edge(a=a, b=b, f2=f2)
                self.edges.add(edge)
            elif f2.count('{}') == 1:
                edge = Edge(a=a, b=b, f2=f2.format(ainfo(a)))
                self.edges.add(edge)
            elif f2.count('{}') == 2:
                edge = Edge(a=a, b=b, f2=f2.format(ainfo(a), binfo(b)))
                self.edges.add(edge)

    def add_edge_ttype(self, a, b, f2, ainfo=None, binfo=None):
        if hasattr(a, 'ttype') or hasattr(b, 'ttype'):
            a = a.ttype if hasattr(a, 'ttype') else a
            b = b.ttype if hasattr(b, 'ttype') else b
            self.add_edge(a, b, f2, ainfo, binfo)

    def add_edge_name_ttype(self, a, b, f2):
        if f2.count('{}') == 0:
            ainfo = None
            binfo = None
        elif f2.count('{}') == 1:
            ainfo = fine if type(a) in FINE_NODES else coarse
            binfo = None
        elif f2.count('{}') == 2:
            ainfo = fine if type(a) in FINE_NODES else coarse
            binfo = fine if type(b) in FINE_NODES else coarse
        self.add_edge(a, b, f2, ainfo, binfo)
        self.add_edge_ttype(a, b, f2, ainfo, binfo)

    def initialize(self):
        for direct_offset in self.binary.direct_offsets.values():
            self.add_edge(
                direct_offset,
                direct_offset.ttype,
                'NAME[{}]TTYPE',
                coarse
            )

            node_type = make_node_type(coarse(direct_offset), self.binary)
            self.add_edge(
                direct_offset,
                node_type,
                'NODE[COARSE]TYPE'
            )

            # node_type = make_node_type(coarse(direct_offset.ttype), self.binary)
            # self.add_edge(
            #     direct_offset.ttype,
            #     node_type,
            #     'NODE[COARSE]TYPE'
            # )

            if isinstance(direct_offset, StringArrayOffset):
                for string_const in direct_offset.strings:
                    self.add_edge(
                        direct_offset,
                        string_const,
                        'STRARR[]ELEM'
                    )

        keys = list(sorted(self.binary.direct_offsets.keys()))
        for key1, key2 in zip(keys[:-1], keys[1:]):
            direct_offset1 = self.binary.direct_offsets[key1]
            direct_offset2 = self.binary.direct_offsets[key2]
            diff = key2 - key1
            if diff <= 0x10:
                self.add_edge(
                    direct_offset1,
                    direct_offset2,
                    'LOCAL{}[DIRECT]'.format(diff)
                )
                self.add_edge(
                    direct_offset1.ttype,
                    direct_offset2.ttype,
                    'LOCAL{}[DIRECT]TTYPE'.format(diff)
                )
                self.add_edge(
                    direct_offset1.ttype,
                    make_size_node(diff, self.binary),
                    'SIZE[DIRECT]TTYPE'
                )

        for function in self.binary.functions.functions:
            if function.is_run_init:
                self.add_edge(
                    function,
                    function.ttype,
                    'NAME[{}]TTYPE',
                    coarse
                )

            node_type = make_node_type(coarse(function), self.binary)
            self.add_edge(
                function,
                node_type,
                'NODE[COARSE]TYPE'
            )

            for callee in function.callees:
                self.add_edge(
                    function,
                    callee,
                    'CALL'
                )
            
            for indirect_offset in function.indirect_offsets.values():
                for off in indirect_offset.values():
                    node_type = make_node_type(fine(off), self.binary)
                    self.add_edge(
                        function,
                        node_type,
                        '[FUNC]NODETYPE[INDIRECT]'
                    )

            if not (self.binary.config.MODE == self.binary.config.TRAIN and not function.init_run):
                for i in function.string_consts:
                    string_const = function.binary.string_consts[i]
                    self.add_edge(
                        string_const,
                        function,
                        'STR[]FUNC'
                    )

                for offset in function.direct_offsets:
                    direct_offset = function.binary.direct_offsets[offset]
                    self.add_edge(
                        direct_offset,
                        function,
                        'DIRECT[]FUNC'
                    )

                for virtual_exp in function.virtual_exps.values():
                    EXP_EDGE_EXTRACTOR.visit(virtual_exp.exp, function=function)

                for indirect_offset in function.indirect_offsets.values():
                    for off in indirect_offset.values():
                        # self.add_edge(
                        #     off,
                        #     function,
                        #     'INDIRECT[{}]FUNC',
                        #     coarse
                        # )
                        self.add_edge(
                            off,
                            function,
                            'INDIRECT[{}]FUNC',
                            fine
                        )
                        # self.add_edge(
                        #     off,
                        #     off.ttype,
                        #     'NAME[{}]TTYPE',
                        #     coarse
                        # )
                        self.add_edge(
                            off,
                            off.ttype,
                            'NAME[{}]TTYPE',
                            fine
                        )
                        # node_type = make_node_type(coarse(off), self.binary)
                        # self.add_edge(
                        #     off,
                        #     node_type,
                        #     'NODE[COARSE]TYPE'
                        # )
                        self.add_edge(
                            off,
                            node_type,
                            'NODE[FINE]TYPE'
                        )
                        # node_type = make_node_type(fine(off.ttype), self.binary)
                        # self.add_edge(
                        #     off.ttype,
                        #     node_type,
                        #     'NODE[FINE]TYPE'
                        # )

                for reg in function.regs.values():
                    self.add_edge(
                        reg,
                        function,
                        'REG[{}]FUNC',
                        coarse
                    )
                    if self.binary.config.MACHINE_ARCH in ('x64', 'ARM') \
                            and reg.var_type == constants.FUN_ARG:
                        self.add_edge(
                            reg,
                            function,
                            'REG[{}]FUNC',
                            fine
                        )
                    self.add_edge(
                        reg,
                        reg.ttype,
                        'NAME[{}]TTYPE',
                        coarse
                    )
                    node_type = make_node_type(coarse(reg), self.binary)
                    self.add_edge(
                        reg,
                        node_type,
                        'NODE[COARSE]TYPE'
                    )
                    # node_type = make_node_type(coarse(reg.ttype), self.binary)
                    # self.add_edge(
                    #     reg.ttype,
                    #     node_type,
                    #     'NODE[FINE]TYPE'
                    # )

                for key in function.indirect_offsets:
                    for i in range(1, self.binary.config.ADDRESS_BYTE_SIZE + 1):
                        key_1 = (key[0], key[1] + i)
                        if key_1 in function.indirect_offsets:
                            indirect_offsets = function.indirect_offsets[key]
                            indirect_offsets_1 = function.indirect_offsets[key_1]
                            for index in indirect_offsets:
                                if index in indirect_offsets_1:
                                    indirect_offset = indirect_offsets[index]
                                    indirect_offset_1 = indirect_offsets_1[index]
                                    # self.add_edge(
                                    #     indirect_offset,
                                    #     indirect_offset_1,
                                    #     'LOCAL[{}]',
                                    #     coarse
                                    # )
                                    self.add_edge(
                                        indirect_offset,
                                        indirect_offset_1,
                                        '[{}]LOCAL[{}]',
                                        fine, fine
                                    )

                for key in function.regs:
                    key_1 = (key[0], key[1] + 1)
                    if key_1 in function.regs:
                        reg = function.regs[key]
                        reg_1 = function.regs[key_1]
                        self.add_edge(
                            reg,
                            reg_1,
                            'LOCAL[{}]',
                            coarse
                        )

        for function in self.binary.functions.functions:
            if not (self.binary.config.MODE == self.binary.config.TRAIN and not function.init_run):
                for blk in function.blks.values():
                    for stmt in blk.stmts:
                        STMT_EDGE_EXTRACTOR.visit(stmt, function=function)

    def dump(self):
        for edge in sorted(self.edges, key=lambda e: e.f2):
            if isinstance(edge.a, Ttype):
                print('({} {} {})'.format(edge.a, edge.b, edge.f2))

    def to_json(self):
        query = []
        for edge in self.edges:
            query.append(OrderedDict([('a', edge.a.id), ('b', edge.b.id), ('f2', edge.f2)]))
        return query

    def stat(self):
        for edge in self.edges:
            key = (type(edge.a), type(edge.b))
            if key not in self.stat_dict:
                self.stat_dict[key] = 0
            self.stat_dict[key] += 1


class Edge:
    def __init__(self, *args, **kwargs):
        self.a = kwargs['a']
        self.b = kwargs['b']
        self.f2 = kwargs['f2']

    def __eq__(self, other):
        return self.a.id == other.a.id \
            and self.b.id == other.b.id \
            and self.f2 == other.f2

    def __hash__(self):
        return hash((self.a.id, self.b.id, self.f2))
