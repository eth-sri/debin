from elements.elmfactory import STMT_TRANSFORMER, STMT_INITIALIZER
from elements.conventions import call_args, prologue, epilogue, temp_offsets
from elements.regs import Reg, GivReg
from elements.offsets import IndirectOffset
from elements.givs import Flag
from elements.featurefactory import EXP_FEATURE_EXTRACTOR, STMT_FEATURE_EXTRACTOR, add_unary_feature, add_binary_feature
from depgraph.infos import fine, coarse
from depgraph.edgefactory import EXP_ELMS_EXTRACTOR
from bap.stmts import DefStmt, PhiStmt, JmpStmt
from bap.vars import VirtualVar


class Blk:
    context = 2

    def __init__(self, *args, **kwargs):
        self.bap = kwargs['bap']
        self.tid = self.bap.tid
        self.function = kwargs['function']
        self.binary = self.function.binary
        self.callees = set()
        self.callers = set()
        self.stmts = []

        temp_offsets(self)
        for stmt_bap in self.bap.stmts:
            STMT_INITIALIZER.visit(stmt_bap, blk=self, pc=stmt_bap.pc)
        if self.binary.config.MACHINE_ARCH in ('x86', 'x64'):
            prologue(self)

    def add_callee(self, callee):
        self.callees.add(callee)

    def add_caller(self, caller):
        self.callers.add(caller)

    def initialize(self):
        call_args(self)
        if self.binary.config.MACHINE_ARCH == 'ARM':
            prologue(self)
        epilogue(self)
        for stmt_bap in self.bap.stmts:
            stmt = STMT_TRANSFORMER.visit(stmt_bap, blk=self, pc=stmt_bap.pc)
            if stmt is not None:
                self.stmts.append(stmt)

    def init_features(self):
        def_stmts = []

        for stmt in self.stmts:
            STMT_FEATURE_EXTRACTOR.visit(stmt, function=self.function)

            if isinstance(stmt, DefStmt):
                def_stmts.append(stmt)

        self.def_features(def_stmts)

    def def_features(self, def_stmts):
        for stmt in def_stmts:
            EXP_FEATURE_EXTRACTOR.visit(stmt.rhs)

        defs = list(map(lambda d: (d.insn, d.lhs, EXP_ELMS_EXTRACTOR.visit(d.rhs, function=self.function)), def_stmts))

        for i in range(0, len(defs)):
            insn = defs[i][0]
            lhs = defs[i][1]
            rhs_elms = defs[i][2]

            if insn is not None:
                feature = 'INSNL[{}][{}]'.format(insn, '{}')
                add_unary_feature(feature, lhs)

                for j, elm in enumerate(rhs_elms):
                    feature = 'DEP[{}][{}][{}]'.format('{}', insn, '{}')
                    add_binary_feature(feature, lhs, elm)

            for j in range(max(0, i - Blk.context), min(len(defs), i + Blk.context + 1)):
                if i != j:
                    context_num = j - i
                    context_insn = defs[j][0]
                    context_lhs = defs[j][1]
                    context_rhs_elms = defs[j][2]

                    if context_insn is not None:
                        feature = 'INSNL[C{}][{}][{}]'.format(context_num, context_insn, '{}')
                        add_unary_feature(feature, lhs)

                    feature = 'DEP[CLHS{}][{}][{}]'.format(context_num, '{}', '{}')
                    add_binary_feature(feature, lhs, context_lhs)

                    for k, context_rhs_elm in enumerate(context_rhs_elms):
                        feature = 'DEP[CRHS{}][{}][{}]'.format(context_num, '{}', '{}')
                        add_binary_feature(feature, lhs, elm)

            for j, elm in enumerate(rhs_elms):
                for j in range(max(0, i - Blk.context), min(len(defs), i + Blk.context + 1)):
                    if i != j:
                        context_num = j - i
                        context_insn = defs[j][0]
                        context_lhs = defs[j][1]
                        context_rhs_elms = defs[j][2]

                        if context_insn is not None:
                            feature = 'INSNR[CRHS{}][{}][{}]'.format(context_num, context_insn, '{}')
                            add_unary_feature(feature, elm)

                        feature = 'ELM[CLHS{}][{}][{}]'.format(context_num, '{}', '{}')
                        add_binary_feature(feature, elm, context_lhs)

                        for k, context_rhs_elm in enumerate(context_rhs_elms):
                            feature = 'ELM[CRHS{}][{}][{}]'.format(context_num, '{}', '{}')
                            add_binary_feature(feature, elm, context_rhs_elm)
