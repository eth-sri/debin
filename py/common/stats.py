from elements.function import Function
from elements.offsets import Offset, GivOffset, DirectOffset
from elements.offsets import StringArrayOffset, IndirectOffset, TempOffset
from elements.regs import RegBase, GivReg, Reg
from elements.givs import GivElm, IntConst, StringConst
from elements.givs import Flag, Insn, CodeOffset, VirtualElm
from elements.givs import SwitchTable, NodeType, OpNode, OtherVarNode
from elements.ttype import Ttype
from depgraph.nodes import INF_NODES
from common.constants import UNKNOWN_LABEL
from common.timer import TIMER


class Stats:
    def __init__(self, binary):
        self.binary = binary
        self.corrects = dict()
        self.errors = dict()
        self.stated = False

    def stat(self):
        if not self.stated:
            self.stated = True

            self.binary.nodes.stat()
            self.binary.edges.stat()

            self.name_known = Function.known + Offset.known + Reg.known
            self.name_unknown = Function.unknown + Offset.unknown + Reg.unknown
            self.name_inf = Function.inf + Offset.inf + Reg.inf
            self.name_correct = Function.correct + Offset.correct + RegBase.correct

            self.known = self.name_known + Ttype.known
            self.unknown = self.name_unknown + Ttype.unknown
            self.inf = self.name_inf + Ttype.inf
            self.giv = Function.giv + Reg.giv + Offset.giv + GivElm.total
            self.total = self.name_inf + Ttype.inf + self.giv
            self.tp_1p = Offset.tp_1p + RegBase.tp_1p
            self.fp_1p = Offset.fp_1p + RegBase.fp_1p
            self.tn_1p = Offset.tn_1p + RegBase.tn_1p
            self.fn_1p = Offset.fn_1p + RegBase.fn_1p
            self.correct = self.name_correct + Ttype.correct

    def stat_result(self, nodes_json):
        for node_json in nodes_json:
            if 'inf' in node_json and node_json['inf'] != UNKNOWN_LABEL:
                node = self.binary.nodes.nodes[node_json['v']]
                train_name = node.train_name
                test_name = node_json['inf']
                if train_name == test_name:
                    if type(node) is IndirectOffset:
                        IndirectOffset.correct += 1
                        Offset.correct += 1
                    elif type(node) is DirectOffset:
                        DirectOffset.correct += 1
                        Offset.correct += 1
                    elif type(node) is StringArrayOffset:
                        StringArrayOffset.correct += 1
                        DirectOffset.correct += 1
                        Offset.correct += 1
                    elif type(node) is Reg:
                        Reg.correct += 1
                        RegBase.correct += 1
                    elif type(node) is Function:
                        Function.correct += 1
                    elif type(node) is Ttype:
                        Ttype.correct += 1
                        type(node.owner).ttype_correct += 1
                        if isinstance(node.owner, StringArrayOffset):
                            DirectOffset.ttype_correct += 1

        for node in self.binary.nodes.nodes.values():
            if type(node) in INF_NODES \
                    and not (isinstance(node, Function) and node.is_name_given) \
                    and not (isinstance(node, DirectOffset) and node.is_name_given):
                if node.train_name == node.test_name:
                    if (node.train_name, node.test_name) not in self.corrects:
                        self.corrects[(node.train_name, node.test_name)] = 0
                    self.corrects[(node.train_name, node.test_name)] += 1
                else:
                    if (node.train_name, node.test_name) not in self.errors:
                        self.errors[(node.train_name, node.test_name)] = 0
                    self.errors[(node.train_name, node.test_name)] += 1

    def dump_corrects(self):
        corrects = sorted(self.corrects.items(), key=lambda i: i[1], reverse=True)
        with open(self.binary.config.CORRECTS_PATH, 'w') as w:
            for c in corrects:
                w.write('\t{} : {} -> {}\n'.format(c[1], c[0][0], c[0][1]))

    def dump_errors(self):
        errors = sorted(self.errors.items(), key=lambda i: i[1], reverse=True)
        with open(self.binary.config.ERRORS_PATH, 'w') as w:
            for e in errors:
                w.write('\t{} : {} -> {}\n'.format(e[1], e[0][0], e[0][1]))

    def dump(self):
        with open(self.binary.config.STAT_PATH, 'w') as w:
            w.write('path: {}\n'.format(self.binary.config.BINARY_PATH))
            w.write('\n')

            denominator = self.tp_1p + self.fp_1p
            precision_1p = self.tp_1p / denominator if denominator != 0 else 0
            denominator = self.tp_1p + self.fn_1p
            recall_1p = self.tp_1p / denominator if denominator != 0 else 0
            denominator = precision_1p + recall_1p
            f1_1p = 2 * precision_1p * recall_1p / denominator if denominator != 0 else 0
            denominator = self.tp_1p + self.fp_1p + self.tn_1p + self.fn_1p
            accuracy_1p = (self.tp_1p + self.tn_1p) / denominator if denominator != 0 else 0
            w.write('precision_1p: {}\n'.format(precision_1p))
            w.write('recall_1p: {}\n'.format(recall_1p))
            w.write('f1_1p: {}\n'.format(f1_1p))
            w.write('accuracy_1p: {}\n'.format(accuracy_1p))
            w.write('\n')

            precision_2p = self.correct / self.inf if self.inf != 0 else 0
            recall_2p = self.correct / self.known if self.known != 0 else 0
            denominator = recall_2p + precision_2p
            f1_2p = 2 * recall_2p * precision_2p / denominator if denominator != 0 else 0
            w.write('precision_2p: {}\n'.format(precision_2p))
            w.write('recall_2p: {}\n'.format(recall_2p))
            w.write('f1_2p: {}\n'.format(f1_2p))
            w.write('\n')

            precision_name_2p = self.name_correct / self.name_inf if self.name_inf != 0 else 0
            recall_name_2p = self.name_correct / self.name_known if self.name_known != 0 else 0
            denominator = recall_name_2p + precision_name_2p
            f1_name_2p = 2 * recall_name_2p * precision_name_2p / denominator if denominator != 0 else 0
            w.write('precision_name_2p: {}\n'.format(precision_name_2p))
            w.write('recall_name_2p: {}\n'.format(recall_name_2p))
            w.write('f1_name_2p: {}\n'.format(f1_name_2p))
            w.write('\n')

            precision_ttype_2p = Ttype.correct / Ttype.inf if Ttype.inf != 0 else 0
            recall_ttype_2p = Ttype.correct / Ttype.known if Ttype.known != 0 else 0
            denominator = recall_ttype_2p + precision_ttype_2p
            f1_ttype_2p = 2 * recall_ttype_2p * precision_ttype_2p / denominator if denominator != 0 else 0
            w.write('precision_ttype_2p: {}\n'.format(precision_ttype_2p))
            w.write('recall_ttype_2p: {}\n'.format(recall_ttype_2p))
            w.write('f1_ttype_2p: {}\n'.format(f1_ttype_2p))
            w.write('\n')

            w.write('time:\n')
            w.write(str(TIMER))
            w.write('\n\n')

            w.write('total: {}\n'.format(self.total))
            w.write('known: {}\n'.format(self.known))
            w.write('unknown: {}\n'.format(self.unknown))
            w.write('inf: {}\n'.format(self.inf))
            w.write('correct: {}\n'.format(self.correct))
            w.write('\n')

            w.write('name_known: {}\n'.format(self.name_known))
            w.write('name_unknown: {}\n'.format(self.name_unknown))
            w.write('name_inf: {}\n'.format(self.name_inf))
            w.write('name_correct: {}\n'.format(self.name_correct))
            w.write('\n')

            w.write('ttype_known: {}\n'.format(Ttype.known))
            w.write('ttype_unknown: {}\n'.format(Ttype.unknown))
            w.write('ttype_inf: {}\n'.format(Ttype.inf))
            w.write('ttype_correct: {}\n'.format(Ttype.correct))
            w.write('\n')

            w.write('function_total: {}\n'.format(Function.total))
            w.write('function_known: {}\n'.format(Function.known))
            w.write('function_unknown: {}\n'.format(Function.unknown))
            w.write('function_inf: {}\n'.format(Function.inf))
            w.write('function_correct: {}\n'.format(Function.correct))
            w.write('\n')

            w.write('reg_total: {}\n'.format(Reg.total))
            w.write('reg_known: {}\n'.format(Reg.known))
            w.write('reg_unknown: {}\n'.format(Reg.unknown))
            w.write('reg_inf: {}\n'.format(Reg.inf))
            w.write('reg_tp_1p: {}\n'.format(RegBase.tp_1p))
            w.write('reg_fp_1p: {}\n'.format(RegBase.fp_1p))
            w.write('reg_tn_1p: {}\n'.format(RegBase.tn_1p))
            w.write('reg_fn_1p: {}\n'.format(RegBase.fn_1p))
            w.write('reg_correct: {}\n'.format(Reg.correct))
            w.write('\n')

            w.write('offset_total: {}\n'.format(Offset.total))
            w.write('offset_known: {}\n'.format(Offset.known))
            w.write('offset_unknown: {}\n'.format(Offset.unknown))
            w.write('offset_inf: {}\n'.format(Offset.inf))
            w.write('offset_correct: {}\n'.format(Offset.correct))
            w.write('\n')

            w.write('indirectoffset_total: {}\n'.format(IndirectOffset.total))
            w.write('indirectoffset_known: {}\n'.format(IndirectOffset.known))
            w.write('indirectoffset_unknown: {}\n'.format(IndirectOffset.unknown))
            w.write('indirectoffset_inf: {}\n'.format(IndirectOffset.inf))
            w.write('indirectoffset_tp_1p: {}\n'.format(IndirectOffset.tp_1p))
            w.write('indirectoffset_fp_1p: {}\n'.format(IndirectOffset.fp_1p))
            w.write('indirectoffset_tn_1p: {}\n'.format(IndirectOffset.tn_1p))
            w.write('indirectoffset_fn_1p: {}\n'.format(IndirectOffset.fn_1p))
            w.write('indirectoffset_correct: {}\n'.format(IndirectOffset.correct))
            w.write('\n')

            w.write('directoffset_total: {}\n'.format(DirectOffset.total))
            w.write('directoffset_known: {}\n'.format(DirectOffset.known))
            w.write('directoffset_unknown: {}\n'.format(DirectOffset.unknown))
            w.write('directoffset_inf: {}\n'.format(DirectOffset.inf))
            w.write('directoffset_correct: {}\n'.format(DirectOffset.correct))
            w.write('\n')

            w.write('function_ttype_total: {}\n'.format(Function.ttype_total))
            w.write('function_ttype_known: {}\n'.format(Function.ttype_known))
            w.write('function_ttype_unknown: {}\n'.format(Function.ttype_unknown))
            w.write('function_ttype_inf: {}\n'.format(Function.ttype_inf))
            w.write('function_ttype_correct: {}\n'.format(Function.ttype_correct))
            w.write('\n')

            w.write('reg_ttype_total: {}\n'.format(Reg.ttype_total))
            w.write('reg_ttype_known: {}\n'.format(Reg.ttype_known))
            w.write('reg_ttype_unknown: {}\n'.format(Reg.ttype_unknown))
            w.write('reg_ttype_inf: {}\n'.format(Reg.ttype_inf))
            w.write('reg_ttype_correct: {}\n'.format(Reg.ttype_correct))
            w.write('\n')

            w.write('indirectoffset_ttype_total: {}\n'.format(IndirectOffset.ttype_total))
            w.write('indirectoffset_ttype_known: {}\n'.format(IndirectOffset.ttype_known))
            w.write('indirectoffset_ttype_unknown: {}\n'.format(IndirectOffset.ttype_unknown))
            w.write('indirectoffset_ttype_inf: {}\n'.format(IndirectOffset.ttype_inf))
            w.write('indirectoffset_ttype_correct: {}\n'.format(IndirectOffset.ttype_correct))
            w.write('\n')

            w.write('directoffset_ttype_total: {}\n'.format(DirectOffset.ttype_total))
            w.write('directoffset_ttype_known: {}\n'.format(DirectOffset.ttype_known))
            w.write('directoffset_ttype_unknown: {}\n'.format(DirectOffset.ttype_unknown))
            w.write('directoffset_ttype_inf: {}\n'.format(DirectOffset.ttype_inf))
            w.write('directoffset_ttype_correct: {}\n'.format(DirectOffset.ttype_correct))
            w.write('\n')
